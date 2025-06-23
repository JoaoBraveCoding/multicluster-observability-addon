package authz_test

import data.authz

# Test data setup
mock_policy := {
	"spec": {
		"subjects": [
			{"kind": "User", "name": "alice"},
			{"kind": "Group", "name": "admins"},
		],
		"permissions": [{
			"resourceScope": "application",
			"tenants": ["tenant1"],
			"namespaces": ["test-namespace"],
			"applicationSignals": ["metrics", "logs"],
		}],
	}
}

mock_infra_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "infra-user"}],
		"permissions": [{
			"resourceScope": "infrastructure",
			"tenants": ["tenant1"],
			"infrastructureSignals": ["metrics"],
		}],
	},
}

mock_audit_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "audit-user"}],
		"permissions": [{
			"resourceScope": "audit",
			"tenants": ["tenant1"],
			"auditSignals": ["logs"],
		}],
	},
}

mock_wildcard_ns_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "ns-admin"}],
		"permissions": [{
			"resourceScope": "application",
			"tenants": ["tenant1"],
			"namespaces": ["*"],
			"applicationSignals": ["metrics"],
		}],
	},
}

mock_multi_permission_policy := {
	"spec": {
		"subjects": [
			{"kind": "User", "name": "dev@example.com"},
			{"kind": "Group", "name": "developers"},
		],
		"permissions": [
			{
				"resourceScope": "application",
				"tenants": ["*"],
				"namespaces": ["dev", "staging"],
				"applicationSignals": ["metrics", "traces"],
			},
			{
				"resourceScope": "infrastructure",
				"tenants": ["tenant1"],
				"infrastructureSignals": ["metrics"],
			},
		],
	},
}

# Test allowing valid user
test_allow_valid_user if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"user": {"id": "alice", "groups": []},
			"requestedResource": {
				"scope": "application",
				"tenants": ["tenant1"],
				"namespaces": ["test-namespace"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test denying invalid user
test_deny_invalid_user if {
	not authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"user": {"id": "bob", "groups": []},
			"requestedResource": {
				"scope": "application",
				"tenants": ["tenant1"],
				"namespaces": ["test-namespace"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test group membership
test_allow_group_member if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"user": {"id": "charlie", "groups": ["admins"]},
			"requestedResource": {
				"scope": "application",
				"tenants": ["tenant1"],
				"namespaces": ["test-namespace"],
			},
			"requestedSignalType": "logs",
		}
}

# Test tenant mismatch
test_deny_wrong_tenant if {
	not authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"user": {"id": "alice", "groups": []},
			"requestedResource": {
				"scope": "application",
				"tenants": ["tenant2"],
				"namespaces": ["test-namespace"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test infrastructure access
test_allow_infrastructure_access if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_infra_policy}}
		with input as {
			"user": {"id": "infra-user", "groups": []},
			"requestedResource": {
				"scope": "infrastructure",
				"tenants": ["tenant1"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test audit access
test_allow_audit_access if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"audit-policy": mock_audit_policy}}
		with input as {
			"user": {"id": "audit-user", "groups": []},
			"requestedResource": {
				"scope": "audit",
				"tenants": ["tenant1"],
			},
			"requestedSignalType": "logs",
		}
}

# Test wildcard namespace access
test_allow_wildcard_namespace_access if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"wildcard-ns-policy": mock_wildcard_ns_policy}}
		with input as {
			"user": {"id": "ns-admin", "groups": []},
			"requestedResource": {
				"scope": "application",
				"tenants": ["tenant1"],
				"namespaces": ["any-namespace-should-work"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test wildcard tenant access for application
test_allow_wildcard_tenant_access if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_multi_permission_policy}}
		with input as {
			"user": {"id": "dev@example.com", "groups": ["developers"]},
			"requestedResource": {
				"scope": "application",
				"tenants": ["any-tenant-should-work"],
				"namespaces": ["dev"],
			},
			"requestedSignalType": "metrics",
		}
}

# Test second permission in the same policy
test_allow_infra_access_from_multi_permission_policy if {
	authz.allow with data.observability_openshift_io.v1alpha1.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_multi_permission_policy}}
		with input as {
			"user": {"id": "dev@example.com", "groups": []},
			"requestedResource": {
				"scope": "infrastructure",
				"tenants": ["tenant1"],
			},
			"requestedSignalType": "metrics",
		}
}
