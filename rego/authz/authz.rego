package authz

import rego.v1
import data.kubernetes.observabilityaccesspolicies

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
	msg := sprintf("Access Denied: Your user '%s' or groups '%s' are not configured in any ObservabilityAccessPolicies in the hub cluster.", [input.subject, input.groups])
}

deny[msg] if {
	# Rule 2: Deny if the user has policies, but none grant access to the requested TENANT.

	# Collect all policies that match the user and tenant.
	tenant_rules := {rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match(object.get(rule, "tenants", []), input.tenant)
	}

	count(tenant_rules) == 0
	msg := sprintf("Access Denied: You do not have permission for the tenant '%s'.", [input.tenant])
}

deny[msg] if {
	# Rule 3: Deny if the user has policies for the tenant, but not for the requested signal and permission.

	# Find if the user has applicable rules for the tenant.
	tenant_rules := [rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match(object.get(rule, "tenants", []), input.tenant)
	]

	count(tenant_rules) > 0

	# Check if any of those rules grant permission for the signal.
	applicable_rules := [rule |
		some rule in tenant_rules
		some permission in object.get(rule, "permission", [])
		permission == input.permission
		some signal in object.get(rule, "signals", [])
		signal == input.resource
	]

	count(applicable_rules) == 0
	msg := sprintf("Access Denied: You do not have permission '%s' to access the signal '%s' for the tenant '%s'.", [input.permission, input.resource, input.tenant])
}

deny[msg] if {
	# Rule 4: deny read requests for logs for the scopes 'infrastructure' and 'audit' that don't provide the scope label.
	input.permission == "read"
	input.resource == "logs"
	scope := extract_scope(input.extras)
	scope == ""

	msg := "Access Denied: In order to query non-application logs you need to provide the label \"type\" with either \"infrastructure\" or \"audit\" as a value."
}

deny[msg] if {
	# Rule 5: deny read requests for logs for the scopes 'infrastructure' and 'audit' that don't have the correct scope label.
	input.permission == "read"
	input.resource == "logs"
	scope := extract_scope(input.extras)
	scope in {"infrastructure", "audit"}

	
	# Find if the user has applicable rules
	applicable_rules := [rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match(object.get(rule, "tenants", []), input.tenant)
		some permission in object.get(rule, "permission", [])
		permission == input.permission
		some signal in object.get(rule, "signals", [])
		signal == input.resource
	]

	count(applicable_rules) > 0

	every rule in applicable_rules {
			not object.get(rule, "resourceScope", "application") == scope
	}

	msg := sprintf("Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'.", [input.resource, scope, input.tenant])
}

deny[msg] if {
	# Rule 5: Process read requests for scope 'application'
	input.permission == "read"
	scope := "application"

	# Find if the user has applicable rules
	applicable_rules := [rule |
		policy := observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match(object.get(rule, "tenants", []), input.tenant)
		some permission in object.get(rule, "permission", [])
		permission == input.permission
		some signal in object.get(rule, "signals", [])
		signal == input.resource
	]

	count(applicable_rules) > 0

	is_application_scope_denied(applicable_rules, scope)

	msg := sprintf("Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'.", [input.resource, scope, input.tenant])
}

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

# element_match: True if the requested element is in the set of elements or
# is a wildcard.
element_match(elements, requested_element) if {
	some element in elements
	element == "*" # Wildcard element allows access to any requested element
}

element_match(elements, requested_element) if {
	some element in elements
	element == requested_element
}

is_application_scope_denied(applicable_rules, scope) if {
	is_metadata_request(input)

	requested_namespaces := extract_namespaces(input)
	count(requested_namespaces) > 0
	
	missing_namespace_access(scope, input.extras, applicable_rules, requested_namespaces)
}

is_application_scope_denied(applicable_rules, scope) if {
	not is_metadata_request(input)

	requested_namespaces := extract_namespaces(input)
	count(requested_namespaces) == 0
	requested_namespaces = ["*"] # Default to wildcard if no namespaces are specified
	missing_namespace_access(scope, input.extras, applicable_rules, requested_namespaces)
}

missing_namespace_access(scope, extras, applicable_rules, requested_namespaces) if {
	every namespace in requested_namespaces {
		every rule in applicable_rules {
			object.get(rule, "resourceScope", "application") == scope
			not element_match(object.get(rule, "namespaces", []), namespace)
		}
	}
}

# is_metadata_request: True if the request is for metadata only.
is_metadata_request(request_input) if {
	metadata_request := object.get(request_input.extras, "metadataOnly", false)
	metadata_request == true
}

# extract_namespaces: Extracts the list of namespaces from the request input.
extract_namespaces(request_input) := namespace_list if {
	selectors := object.get(request_input.extras, "selectors", {})
	namespace_list := object.get(selectors, "k8s_namespace_name", [])
}

# extract_scope: Extracts the value of the scope label from the request input.
extract_scope(request_input) := scope if {
	selectors := object.get(request_input.extras, "selectors", {})
	scope := object.get(selectors, "type", "")
}
