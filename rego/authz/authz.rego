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

request_metadata_key := "metadataOnly"
request_selectors_key := "selectors"
request_namespace_label_key := "k8s_namespace_name"
request_type_label_key := "type"

missing_policies_deny_message := "Access Denied: Your user '%s' or groups '%s' are not configured in any ObservabilityAccessPolicies in the hub cluster."
unauthorized_tenant_message := "Access Denied: You do not have permission for the tenant '%s'."
missing_type_label := "Access Denied: To query non-application logs you need to provide the label \"type\" with either \"infrastructure\" or \"audit\"."
missing_signal_permissions_for_tenant := "Access Denied: You do not have permission '%s' to access the signal '%s' for the tenant '%s'."
missing_query_permissions_for_tenant := "Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'."
forbidden_namespaces_in_scope := "Access Denied: Your query contains namespaces that are not allowed to be queried with the scope '%s'."

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
	# Rule 1: Deny if the user doesn't match ANY policy at all.

	# Collect all policies that are relevant to this user.
	applicable_policies := {policy |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
	}

	count(applicable_policies) == 0
	msg := sprintf(missing_policies_deny_message, [input.subject, input.groups])
}

deny[msg] if {
	# Rule 2: Deny if the user has policies, but none grant access to the requested TENANT.

	# Collect all policies that match the user and tenant.
	tenant_rules := {rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match_or_wildcard(object.get(rule, rule_tenants_key, []), input.tenant)
	}

	count(tenant_rules) == 0
	msg := sprintf(unauthorized_tenant_message, [input.tenant])
}

deny[msg] if {
	# Rule 3: Deny if the user has policies for the tenant, but not for the requested signal and permission.

	# Find if the user has applicable rules for the tenant.
	tenant_rules := [rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match_or_wildcard(object.get(rule, rule_tenants_key, []), input.tenant)
	]

	count(tenant_rules) > 0

	# Check if any of those rules grant permission for the signal.
	applicable_rules := [rule |
		some rule in tenant_rules
		element_match(object.get(rule, rule_permission_key, []), input.permission)
		element_match(object.get(rule, rule_signals_key, []), input.resource)
	]

	count(applicable_rules) == 0
	msg := sprintf(missing_signal_permissions_for_tenant, [input.permission, input.resource, input.tenant])
}

deny[missing_type_label] if {
	# Rule 4: Deny logs read requests that do not contain application namespaces and are missing the scope label.
	input.resource == log_signal
	input.permission == read_permission
	requested_namespaces := extract_namespaces(input)
	application_namespaces := {ns | some ns in requested_namespaces; not is_infrastructure_namespace(ns)}
	count(application_namespaces) == 0

	extract_scope(input) == ""
}

deny[msg] if {
	# Rule 5: deny logs read requests for scopes 'infrastructure' and 'audit' that don't have the correct permissions
	# to do so.
	input.resource == log_signal
	input.permission == read_permission
	not is_application_scope(extract_scope(input))
	request_scope := extract_scope(input)

	# Find if the user has applicable rules
	applicable_rules := [rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match_or_wildcard(object.get(rule, rule_tenants_key, []), input.tenant)
		element_match(object.get(rule, rule_permission_key, []), input.permission)
		element_match(object.get(rule, rule_signals_key, []), input.resource)
	]

	count(applicable_rules) > 0

	every rule in applicable_rules {
		not object.get(rule, rule_scope_key, application_scope) == request_scope
	}

	msg := sprintf(missing_query_permissions_for_tenant, [input.resource, request_scope, input.tenant])
}

deny[msg] if {
	# Rule 6: deny read requests for logs if the requested scope doesn't match the policy scope/namespaces.
	input.resource == log_signal
	input.permission == read_permission
	request_scope := extract_scope(input)
	request_scope in {application_scope, infrastructure_scope, audit_scope}

	# Find if the user has applicable rules
	applicable_rules := rules_that_match(input.subject, input.groups, input.tenant, input.permission, input.resource, request_scope)

	namespaces_do_not_match_scope(applicable_rules, request_scope)

	msg := sprintf(forbidden_namespaces_in_scope, [request_scope])
}

deny[msg] if {
	# Rule 7: Process read requests for scope 'application'
	input.permission == read_permission
	is_application_scope(extract_scope(input))

	# Find if the user has applicable rules
	applicable_rules := rules_that_match(input.subject, input.groups, input.tenant, input.permission, input.resource, application_scope)
	count(applicable_rules) == 0

	msg := sprintf(missing_query_permissions_for_tenant, [input.resource, application_scope, input.tenant])
}

deny[msg] if {
	# Rule 7: Process read requests for scope 'application'
	input.permission == read_permission
	is_application_scope(extract_scope(input))

	# Find if the user has applicable rules
	applicable_rules := rules_that_match(input.subject, input.groups, input.tenant, input.permission, input.resource, application_scope)
	count(applicable_rules) > 0

	is_logs_application_scope_compliant(input.resource, applicable_rules, application_scope)
	is_application_scope_denied(input, applicable_rules, application_scope)

	msg := sprintf("TODO CHANGE ME Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'.", [input.resource, application_scope, input.tenant])
}

rules_that_match(subject, group, tenant, permission, signal, scope) := [rule |
	policy := observabilityaccesspolicies[_][_]
	subject_matches(policy.spec.subjects, subject, group)
	some rule in policy.spec.accessRules
	element_match_or_wildcard(object.get(rule, rule_tenants_key, []), tenant)
	element_match(object.get(rule, rule_permission_key, []), permission)
	element_match(object.get(rule, rule_signals_key, []), signal)
	object.get(rule, rule_scope_key, application_scope) == scope
]

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

# is_application_scope_denied: True if the request is a query request without specifying a namespace or
# references namespace to which the user does not have access
is_application_scope_denied(request_input, applicable_rules, scope) if {
	requested_namespaces := extract_namespaces(request_input)
	count(requested_namespaces) > 0

	some namespace in requested_namespaces
	every rule in applicable_rules {
		not element_match_or_wildcard(object.get(rule, rule_namespaces_key, []), namespace)
	}
}

is_application_scope_denied(request_input, applicable_rules, scope) if {
	metadata_request := object.get(request_input.extras, request_metadata_key, false)
	metadata_request == false

	requested_namespaces := extract_namespaces(request_input)
	count(requested_namespaces) == 0
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

# is_logs_application_scope_compliant since logs are scoped by application,
# infrastructure and audit, we need to validate that the query doesn't try to
# access namespaces that are not compliant with the scope.
is_logs_application_scope_compliant(signal, applicable_rules, scope) if {
	signal != log_signal
}

is_logs_application_scope_compliant(signal, applicable_rules, scope) if {
	signal == log_signal
	scope == application_scope
	not namespaces_do_not_match_scope(applicable_rules, scope)
}

# namespaces_do_not_match_scope: True if the requested namespaces do not match the scope of the policy.
# mainly used by Log queries.
namespaces_do_not_match_scope(applicable_rules, request_scope) if {
	request_scope == infrastructure_scope
	requested_namespaces := extract_namespaces(input)
	applicable_namespaces := {ns | some ns in requested_namespaces; is_infrastructure_namespace(ns)}
	count(requested_namespaces) != count(applicable_namespaces)
}

namespaces_do_not_match_scope(applicable_rules, request_scope) if {
	request_scope == application_scope
	requested_namespaces := extract_namespaces(input)
	applicable_namespaces := {ns | some ns in requested_namespaces; not is_infrastructure_namespace(ns)}
	count(requested_namespaces) != count(applicable_namespaces)
}

# is_infrastructure_namespace: True if requested namespace is an infrastructure namespace.
is_infrastructure_namespace("default") := "default"

is_infrastructure_namespace(requested_namespace) if {
	startswith(requested_namespace, "openshift-")
}

is_infrastructure_namespace(requested_namespace) if {
	startswith(requested_namespace, "kube-")
}
