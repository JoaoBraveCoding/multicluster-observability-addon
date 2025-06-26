package authz

import rego.v1

# Default to deny all requests
default allow := false

# The main 'allow' rule.
# A request is allowed if any loaded ObservabilityAccessPolicy grants the user the requested access.
allow if {
	policy := data.kubernetes.observabilityaccesspolicies[_][_]

	# Check if the requesting user/group is a subject in this policy
	subject_matches(policy.spec.subjects, input.subject, input.groups)

	# Iterate through the access rules in this policy
	some rule in policy.spec.accessRules

	tenant_signal_access(rule, input)

	# Check if this rule grants access to the requested resource and permission
	permission_granted(rule, input)
}

# --- Subject helper functions ---

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

tenant_signal_access(rule, request_input) if {
	tenants_match(object.get(rule, "tenants", []), request_input.tenant)
	some signal in object.get(rule, "signals", [])
	signal == request_input.resource
}

# rule_scope: Get a rule's resourceScope, defaulting to "application" if absent from the YAML.
rule_scope(rule) := object.get(rule, "resourceScope", "application")

# permission_granted: True if a specific permission rule grants access, rules defined by scope.

# For write operations, only tenant access is required (no namespace or signal restrictions)
permission_granted(rule, request_input) if {
	request_input.permission == "write"
	access_verb_matches(rule, request_input.permission)
}

# For read operations, apply full scope-based restrictions
permission_granted(rule, request_input) if {
	request_input.permission == "read"
	access_verb_matches(rule, request_input.permission)

	scope := rule_scope(rule)
	scope == "application"
	application_namespaces_match(object.get(rule, "namespaces", []), object.get(request_input.extras, "namespace", ""))
}

permission_granted(rule, request_input) if {
	request_input.permission == "read"
	access_verb_matches(rule, request_input.permission)

	scope := rule_scope(rule)
	scope == "infrastructure"
	infrastructure_namespace_match(object.get(request_input.extras, "namespace", ""))
}

permission_granted(rule, request_input) if {
	request_input.permission == "read"
	access_verb_matches(rule, request_input.permission)

	scope := rule_scope(rule)
	scope == "audit"
}

access_verb_matches(rule, permission) if {
	some perm in object.get(rule, "permission", ["read"])
	perm == permission
}

# tenants_match: True if the requested tenant is allowed by the rule.
tenants_match(rule_tenants, requested_tenant) if {
	some tenant in rule_tenants
	tenant == "*" # Wildcard tenant allows access to any requested tenant
}

tenants_match(rule_tenants, requested_tenant) if {
	some tenant in rule_tenants
	tenant == requested_tenant
}

# application_namespaces_match: True if requested namespace is covered (only for 'application' scope).
application_namespaces_match(rule_namespaces, requested_namespace) if {
	count(rule_namespaces) == 0 # Empty list in rule means "all namespaces"
}

application_namespaces_match(rule_namespaces, requested_namespace) if {
	some ns in rule_namespaces
	ns == "*" # Wildcard also means "all namespaces"
}

application_namespaces_match(rule_namespaces, requested_namespace) if {
	some ns in rule_namespaces
	ns == requested_namespace
}

# infrastructure_namespace_match: True if requested namespace is an infrastructure namespace.
infrastructure_namespace_match("default") := "default"

infrastructure_namespace_match(requested_namespace) if {
	startswith(requested_namespace, "openshift-")
}

infrastructure_namespace_match(requested_namespace) if {
	startswith(requested_namespace, "kube-")
}
