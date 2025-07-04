package authz

import data.kubernetes.observabilityaccesspolicies
import rego.v1

log_signal := "logs"

read_permission := "read"
write_permission := "write"

application_scope := "application"
infrastructure_scope := "infrastructure"
audit_scope := "audit"

rule_signals_key := "signals"
rule_tenants_key := "tenants"
rule_namespaces_key := "namespaces"
rule_scope_key := "resourceScope"
rule_permission_key := "permission"

request_selectors_key := "selectors"
request_metadata_key := "metadataOnly"
request_wildcard_selectors_key := "wildcardSelectors"
request_namespace_label_key := "k8s_namespace_name"
request_type_label_key := "type"

unauthorized_wildcard_selectors := "Access Denied: Your user query contains wildcard selectors which are currently unsupported."
missing_policies_deny_message := "Access Denied: Your user '%s' or groups '%s' are not configured in any ObservabilityAccessPolicies in the hub cluster."
unauthorized_tenant_message := "Access Denied: You do not have permission for the tenant '%s'."
missing_type_label := "Access Denied: To query logs you need to provide the label \"type\" with either \"application\", \"infrastructure\" or \"audit\"."
missing_signal_permissions_for_tenant := "Access Denied: You do not have permission '%s' to access the signal '%s' for the tenant '%s'."
missing_query_permissions_for_tenant := "Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'."
forbidden_namespaces_in_scope := "Access Denied: Your log query for the tenant '%s' contains the following namespaces that are not allowed for the scope '%s': %s."
forbidden_namespaces := "Access Denied: Your '%s' query for the tenant '%s' using the scope '%s' contains the following namespaces that are not allowed to be queried: %s."
missing_namespaces := "Access Denied: Your '%s' query for the tenant '%s' using the scope '%s' does not specify any namespaces to query."

# The main 'allow' rule.
# A request is allowed if there are no deny messages.
allow if {
	count(deny) == 0
}

# The new main rule to be queried by the API.
# It composes the final response object.
decision := {
	"allow": allow,
	"deny_reasons": deny,
}

# The 'deny' rule will return a message on why the user was denied access.
deny[msg] if {
	msg := validate_no_wildcard_selectors(input)
}

validate_no_wildcard_selectors(request_input) := unauthorized_wildcard_selectors if {
	# Rule 1: Deny if the request contains wildcard selectors
	object.get(request_input.extras, request_wildcard_selectors_key, false) == true
}

validate_no_wildcard_selectors(request_input) := msg if {
	# Next Rule Path
	object.get(request_input.extras, request_wildcard_selectors_key, false) != true

	# Collect all policies that are relevant to this user.
	applicable_policies := {policy |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, request_input.subject, request_input.groups)
	}

	msg := validate_policies_exist(request_input, applicable_policies)
}

validate_policies_exist(request_input, applicable_policies) := msg if {
	# Rule 2: Deny if the user doesn't match ANY policy at all.

	count(applicable_policies) == 0
	msg := sprintf(missing_policies_deny_message, [request_input.subject, request_input.groups])
}

validate_policies_exist(request_input, applicable_policies) := msg if {
	# Next Rule Path

	# Collect all policies that match the tenant.
	count(applicable_policies) > 0
	tenant_rules := {rule |
		some policy in applicable_policies
		some rule in policy.spec.accessRules
		element_match_or_wildcard(object.get(rule, rule_tenants_key, []), request_input.tenant)
	}

	msg := validate_tenants_referenced(request_input, tenant_rules)
}

validate_tenants_referenced(request_input, tenant_rules) := msg if {
	# Rule 3: Deny if the user has policies, but none grant access to the requested tenant.

	count(tenant_rules) == 0
	msg := sprintf(unauthorized_tenant_message, [request_input.tenant])
}

validate_tenants_referenced(request_input, tenant_rules) := msg if {
	# Next Rule Path
	# Check if any of those rules grant permission for the signal.
	count(tenant_rules) > 0
	applicable_rules := [rule |
		some rule in tenant_rules
		element_match(object.get(rule, rule_permission_key, []), request_input.permission)
		element_match(object.get(rule, rule_signals_key, []), request_input.resource)
	]

	msg := validate_signal_permissions_for_tenant(request_input, applicable_rules)
}

validate_signal_permissions_for_tenant(request_input, applicable_rules) := msg if {
	# Rule 4: Deny if the user has policies for the tenant, but not for the requested signal and permission.

	count(applicable_rules) == 0
	msg := sprintf(missing_signal_permissions_for_tenant, [request_input.permission, request_input.resource, request_input.tenant])
}

validate_signal_permissions_for_tenant(request_input, applicable_rules) := msg if {
	# Next Rule Path

	count(applicable_rules) > 0
	msg := signal_request_validation(request_input, applicable_rules)
}

signal_request_validation(request_input, applicable_rules) := msg if {
	# Skip rule for other signals
	input.resource != log_signal
	input.permission == read_permission

	msg := pre_validate_scope_permissions(request_input, applicable_rules)
}

signal_request_validation(request_input, applicable_rules) := missing_type_label if {
	# Rule 5: Deny logs read requests that are missing the scope label.
	input.resource == log_signal
	input.permission == read_permission

	extract_scope(input) == ""
}

signal_request_validation(request_input, applicable_rules) := msg if {
	# Next Rule Path for Logs
	input.resource == log_signal
	input.permission == read_permission

	extract_scope(input) != ""
	msg := pre_validate_scope_permissions(request_input, applicable_rules)
}

pre_validate_scope_permissions(request_input, applicable_rules) := msg if {
	# Pre validation for scope permissions
	selectors := object.get(input.extras, request_selectors_key, {})
	request_scope := object.get(selectors, request_type_label_key, "application")

	filtered_applicable_rules := [rule |
		some rule in applicable_rules
		object.get(rule, rule_scope_key, application_scope) == request_scope
	]
	msg := validate_scope_permissions(request_input, filtered_applicable_rules, request_scope)
}

validate_scope_permissions(request_input, applicable_rules, request_scope) := msg if {
	# Rule 6: Deny if the user has policies for the tenant and signal, but not for the requested scope.
	count(applicable_rules) == 0
	msg := sprintf(missing_query_permissions_for_tenant, [request_input.resource, request_scope, request_input.tenant])
}

validate_scope_permissions(request_input, applicable_rules, request_scope) := msg if {
	# Next Rule Path for other signals

	input.resource != log_signal
	count(applicable_rules) > 0
	is_application_scope(extract_scope(request_input))

	msg := validate_application_query(request_input, applicable_rules, request_scope)
}

validate_scope_permissions(request_input, applicable_rules, request_scope) := msg if {
	# Next Rule Path for Logs

	input.resource == log_signal
	count(applicable_rules) > 0

	invalid_namespaces := extract_namespaces_outside_of_scope(applicable_rules, request_scope)
	msg := validate_scope_namespace_conflicts(request_input, applicable_rules, request_scope, invalid_namespaces)
}

validate_application_query(request_input, applicable_rules, request_scope) := msg if {
	# Rule 7: Deny if the user has policies for the tenant and signal, but not for the requested namespaces.
	unauthorized_namespaces := extract_unauthorized_namespaces(input, applicable_rules, request_scope)
	count(unauthorized_namespaces) > 0
	msg := sprintf(forbidden_namespaces, [request_input.resource, request_input.tenant, request_scope, unauthorized_namespaces])
}

validate_application_query(request_input, applicable_rules, request_scope) := msg if {
	metadata_request := object.get(request_input.extras, request_metadata_key, false)
	metadata_request == false

	requested_namespaces := extract_namespaces(request_input)
	count(requested_namespaces) == 0
	msg := sprintf(missing_namespaces, [request_input.resource, request_input.tenant, request_scope])
}

validate_scope_namespace_conflicts(request_input, applicable_rules, request_scope, invalid_namespaces) := msg if {
	# Rule 8: Deny if the user has policies for the tenant and signal, but the requested namespaces do not match the scope.
	count(invalid_namespaces) > 0
	msg := sprintf(forbidden_namespaces_in_scope, [request_input.tenant, request_scope, invalid_namespaces])
}

validate_scope_namespace_conflicts(request_input, applicable_rules, request_scope, invalid_namespaces) := msg if {
	# Next Rule Path for Logs Scope Application
	count(invalid_namespaces) == 0
	is_application_scope(extract_scope(request_input))
	msg := validate_application_query(request_input, applicable_rules, request_scope)
}

# element_match: True if the requested element is in the set of elements or
# is a wildcard.
element_match(elements, requested_element) if {
	some element in elements
	element == requested_element
}

# element_match_or_wildcard: True if the requested element is in the set of elements or
# is a wildcard.
element_match_or_wildcard(elements, requested_element) if {
	some element in elements
	element == "*" # Wildcard element allows access to any requested element
}

element_match_or_wildcard(elements, requested_element) if {
	element_match(elements, requested_element)
}

# is_application_scope: True if the request is for the application scope or
# doesn't specify a scope.
is_application_scope(request_scope) if {
	request_scope in {application_scope, ""}
}

# extract_unauthorized_namespaces: True if the request is a query request without specifying a namespace or
# references namespace to which the user does not have access
extract_unauthorized_namespaces(request_input, applicable_rules, scope) := unauthorized_namespaces if {
	requested_namespaces := extract_namespaces(request_input)
	count(requested_namespaces) > 0

	unauthorized_namespaces := {namespace |
		some namespace in requested_namespaces
		every rule in applicable_rules {
			not element_match_or_wildcard(object.get(rule, rule_namespaces_key, []), namespace)
		}
	}
}

# extract_namespaces: Extracts the list of namespaces from the request input.
extract_namespaces(request_input) := namespace_list if {
	selectors := object.get(request_input.extras, request_selectors_key, {})
	namespace_list := object.get(selectors, request_namespace_label_key, [])
}

# extract_scope: Extracts the value of the scope label from the request input.
extract_scope(request_input) := scope if {
	selectors := object.get(request_input.extras, request_selectors_key, {})
	scope := object.get(selectors, request_type_label_key, "")
}

# ---- Tenant Helper Rules ----

# subject_matches: True if the user or any of their groups match a subject in the policy.
subject_matches(policy_subjects, user_subject, user_groups) if {
	some subject in policy_subjects
	subject.kind == "User"
	subject.name == user_subject
}

subject_matches(policy_subjects, user_subject, user_groups) if {
	some subject in policy_subjects
	some group in user_groups
	subject.kind == "Group"
	subject.name == group
}

# ---- Log Specific Helper Rules ----

# extract_namespaces_outside_of_scope: True if the requested namespaces do not match the scope of the policy.
# mainly used by Log queries.
extract_namespaces_outside_of_scope(applicable_rules, request_scope) := invalid_namespaces if {
	request_scope == infrastructure_scope
	requested_namespaces := extract_namespaces(input)
	invalid_namespaces := {ns | some ns in requested_namespaces; not is_infrastructure_namespace(ns)}
}

extract_namespaces_outside_of_scope(applicable_rules, request_scope) := invalid_namespaces if {
	request_scope == application_scope
	requested_namespaces := extract_namespaces(input)
	invalid_namespaces := {ns | some ns in requested_namespaces; is_infrastructure_namespace(ns)}
}

# is_infrastructure_namespace: True if requested namespace is an infrastructure namespace.
is_infrastructure_namespace("default") := "default"

is_infrastructure_namespace(requested_namespace) if {
	startswith(requested_namespace, "openshift-")
}

is_infrastructure_namespace(requested_namespace) if {
	startswith(requested_namespace, "kube-")
}
