package authz

import rego.v1

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
		policy := data.kubernetes.observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
	}

	count(applicable_policies) == 0
	msg := "Access Denied: Your user or group is not configured in any ObservabilityAccessPolicies in the hub cluster."
}

deny[msg] if {
	# Rule 2: Deny if the user has policies, but none grant access to the requested TENANT.

	# Collect all policies that match the user and tenant.
	tenant_rules := {rule |
		policy := data.kubernetes.observabilityaccesspolicies[_][_]
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
		policy := data.kubernetes.observabilityaccesspolicies[_][_]
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
	# Rule 4: Process read requests and deny any that do not meet scope conditions.
	input.permission == "read"

	# Find if the user has applicable rules
	applicable_rules := [rule |
		policy := data.kubernetes.observabilityaccesspolicies[_][_]
		subject_matches(policy.spec.subjects, input.subject, input.groups)
		some rule in policy.spec.accessRules
		element_match(object.get(rule, "tenants", []), input.tenant)
		some permission in object.get(rule, "permission", [])
		permission == input.permission
		some signal in object.get(rule, "signals", [])
		signal == input.resource
	]

	count(applicable_rules) > 0

	# Check for scope violations
	some scope in {"audit", "application", "infrastructure"}
	is_scope_denied(applicable_rules, scope)

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

is_scope_denied(applicable_rules, scope) if {
	# Rule 2: Deny requests with no namespaces (audit requests) that don't have a
	# rule that allows it.
	scope == "audit"

	# For audit scope, we allow access if no namespaces are requested. As audit
	# logs don't have specify a namespace.
	requested_namespaces := extract_namespaces(input)
	count(requested_namespaces) == 0

	every rule in applicable_rules {
		not object.get(rule, "resourceScope", "application") == scope
	}
}

is_scope_denied(applicable_rules, scope) if {
	# Rule 4: Deny requests with application namespaces that don't have a rule that for every
	# namespace requested doesn't allow it.
	scope == "application"

	requested_namespaces := extract_namespaces(input)
	applicable_namespaces := {ns | some ns in requested_namespaces; not infrastructure_namespace_match(ns)}

	validate_namespace_access(scope, input.extras, applicable_rules, applicable_namespaces)
}

is_scope_denied(applicable_rules, scope) if {
	# Rule 3: Deny requests with infra namespaces that don't have a rule that for every
	# infrastructure namespace requested doesn't allow it.
	scope == "infrastructure"

	requested_namespaces := extract_namespaces(input)
	applicable_namespaces := {ns | some ns in requested_namespaces; infrastructure_namespace_match(ns)}

	validate_infra_namespace_access(scope, input.extras, applicable_rules, applicable_namespaces)
}

validate_namespace_access(scope, extras, applicable_rules, applicable_namespaces) if {
	metadata_request(input.extras)
	count(applicable_namespaces) == 0
	every rule in applicable_rules {
			not object.get(rule, "resourceScope", "application") == scope
	}
}

validate_namespace_access(scope, extras, applicable_rules, applicable_namespaces) if {
	not metadata_request(input.extras)
	count(applicable_namespaces) > 0
	every namespace in applicable_namespaces {
		every rule in applicable_rules {
			object.get(rule, "resourceScope", "application") == scope
			not element_match(object.get(rule, "namespaces", []), namespace)
		}
	}
}

validate_infra_namespace_access(scope, extras, applicable_rules, applicable_namespaces) if {
	validate_namespace_access(scope, extras, applicable_rules, applicable_namespaces)
}

validate_infra_namespace_access(scope, extras, applicable_rules, applicable_namespaces) if {
	not metadata_request(extras)
	count(applicable_namespaces) == 0
	every rule in applicable_rules {
			not object.get(rule, "resourceScope", "application") == scope
	}
}

# metadata_request: True if the request is for metadata only.
metadata_request(extras) if {
	metadata_request := object.get(extras, "metadataOnly", false)
	metadata_request == true
}

# extract_namespaces: Extracts the list of namespaces from the request input.
extract_namespaces(request_input) := namespace_list if {
	selectors := object.get(request_input.extras, "selectors", {})
	namespace_list := object.get(selectors, "k8s_namespace_name", [])
}

# infrastructure_namespace_match: True if requested namespace is an infrastructure namespace.
infrastructure_namespace_match("default") := "default"

infrastructure_namespace_match(requested_namespaces) if {
	startswith(requested_namespaces, "openshift-")
}

infrastructure_namespace_match(requested_namespaces) if {
	startswith(requested_namespaces, "kube-")
}
