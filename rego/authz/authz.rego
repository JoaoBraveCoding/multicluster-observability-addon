package authz

import rego.v1

# Default to deny all requests
default allow := false

# The main 'allow' rule.
# A request is allowed if any loaded ObservabilityAccessPolicy grants the user the requested access.
allow if {
	# The path to the data is structured by kube-mgmt based on the CRD's GVK and namespace/name.
	# CHANGED: Updated the path to match the new apiGroup "observability.openshift.io"
	policy := data.observability_openshift_io.v1alpha1.observabilityaccesspolicies[_][_]

	# Check if the requesting user/group is a subject in this policy
	subject_matches(policy.spec.subjects, input.user)

	# Iterate through the permission rules in this policy
	some rule in policy.spec.permissions

	# Check if this rule grants access to the requested resource and signal type
	permission_granted(rule, input.requestedResource, input.requestedSignalType)
}

# --- Helper Functions ---

# subject_matches: True if the user or any of their groups match a subject in the policy.
subject_matches(policy_subjects, input_user) if {
	some subject in policy_subjects
	subject.kind == "User"
	subject.name == input_user.id
}

subject_matches(policy_subjects, input_user) if {
	some subject in policy_subjects
	some group in input_user.groups
	subject.kind == "Group"
	subject.name == group
}

# rule_scope: Get a rule's resourceScope, defaulting to "application" if absent from the YAML.
rule_scope(rule) := object.get(rule, "resourceScope", "application")

# permission_granted: True if a specific permission rule grants access.
permission_granted(rule, requested_resource, requested_signal_type) if {
	# 1. Match the Resource Scope
	rule_scope(rule) == requested_resource.scope

	# 2. Check if requested tenants are covered by this rule's tenants
	tenants_match(object.get(rule, "tenants", []), requested_resource.tenants)

	# 3. Check scope-specific permissions (signals and namespaces)
	scope := rule_scope(rule)

	# Application scope
	scope == "application"
	namespaces_match(object.get(rule, "namespaces", []), object.get(requested_resource, "namespaces", []))
	some signal in object.get(rule, "applicationSignals", [])
	signal == requested_signal_type
}

permission_granted(rule, requested_resource, requested_signal_type) if {
	# 1. Match the Resource Scope
	rule_scope(rule) == requested_resource.scope

	# 2. Check if requested tenants are covered by this rule's tenants
	tenants_match(object.get(rule, "tenants", []), requested_resource.tenants)

	# 3. Infrastructure scope
	scope := rule_scope(rule)
	scope == "infrastructure"
	some signal in object.get(rule, "infrastructureSignals", [])
	signal == requested_signal_type
}

permission_granted(rule, requested_resource, requested_signal_type) if {
	# 1. Match the Resource Scope
	rule_scope(rule) == requested_resource.scope

	# 2. Check if requested tenants are covered by this rule's tenants
	tenants_match(object.get(rule, "tenants", []), requested_resource.tenants)

	# 3. Audit scope
	scope := rule_scope(rule)
	scope == "audit"
	some signal in object.get(rule, "auditSignals", [])
	signal == requested_signal_type
}

# tenants_match: True if the set of requested tenants is a subset of the allowed tenants in the rule.
tenants_match(rule_tenants, requested_tenants) if {
	some tenant in rule_tenants
	tenant == "*" # Wildcard tenant allows access to any requested tenant
}

tenants_match(rule_tenants, requested_tenants) if {
	# Otherwise, all requested tenants must be in the rule's tenants list.
	allowed_set := {t | some t in rule_tenants}
	every req_tenant in requested_tenants {
		allowed_set[req_tenant]
	}
}

# namespaces_match: True if requested namespaces are covered (only for 'application' scope).
namespaces_match(rule_namespaces, requested_namespaces) if {
	count(rule_namespaces) == 0 # Empty list in rule means "all namespaces"
}

namespaces_match(rule_namespaces, requested_namespaces) if {
	some ns in rule_namespaces
	ns == "*" # Wildcard also means "all namespaces"
}

namespaces_match(rule_namespaces, requested_namespaces) if {
	# Otherwise, all requested namespaces must be in the rule's list.
	allowed_set := {ns | some ns in rule_namespaces}
	every req_ns in requested_namespaces {
		allowed_set[req_ns]
	}
}
