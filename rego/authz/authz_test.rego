package authz_test

import data.authz

# Test data setup
mock_policy := {
	"spec": {
		"subjects": [
			{"kind": "User", "name": "alice"},
			{"kind": "Group", "name": "admins"},
		],
		"accessRules": [{
			"resourceScope": "application",
			"tenants": ["tenant1"],
			"namespaces": ["test-namespace"],
			"signals": ["metrics", "logs"],
			"permission": ["read"]
		}],
	}
}
mock_write_policy := {
	"spec": {
		"subjects": [
			{"kind": "Group", "name": "writers"},
		],
		"accessRules": [{
			"resourceScope": "infrastructure",
			"tenants": ["tenant1"],
			"signals": ["metrics", "logs"],
			"permission": ["write"]
		}],
	}
}

mock_read_infra_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "infra-user"}],
		"accessRules": [{
			"resourceScope": "infrastructure",
			"tenants": ["tenant1"],
			"signals": ["metrics"],
			"permission": ["read"]
		}],
	},
}

mock_write_infra_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "infra-user"}],
		"accessRules": [{
			"resourceScope": "infrastructure",
			"tenants": ["tenant1"],
			"signals": ["metrics"],
			"permission": ["write"]
		}],
	},
}

mock_audit_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "audit-user"}],
		"accessRules": [{
			"resourceScope": "audit",
			"tenants": ["tenant1"],
			"signals": ["logs"],
			"permission": ["read"]
		}],
	},
}

mock_wildcard_ns_policy := {
	"spec": {
		"subjects": [{"kind": "User", "name": "ns-admin"}],
		"accessRules": [{
			"resourceScope": "application",
			"tenants": ["tenant1"],
			"namespaces": ["*"],
			"signals": ["metrics"],
			"permission": ["read"]
		}],
	},
}

mock_multi_permission_policy := {
	"spec": {
		"subjects": [
			{"kind": "User", "name": "dev@example.com"},
			{"kind": "Group", "name": "developers"},
		],
		"accessRules": [
			{
				"resourceScope": "application",
				"tenants": ["*"],
				"namespaces": ["dev", "staging"],
				"signals": ["metrics", "traces"],
				"permission": ["read"]
			},
			{
				"resourceScope": "infrastructure",
				"tenants": ["tenant1"],
				"signals": ["metrics"],
				"permission": ["read"]
			},
		],
	},
}

# Test allowing valid user
test_allow_valid_user if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			}
		}
}

# Test denying invalid user
test_deny_invalid_user if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "bob",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			}
		}
}

# Test group membership
test_allow_group_member if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "charlie",
			"groups": ["admins"],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			}
		}
}

# Test tenant mismatch
test_deny_wrong_tenant if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant2",
			"tenantID": "67890",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			}
		}
}

# Test infrastructure access
test_allow_infrastructure_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_read_infra_policy}}
		with input as {
			"subject": "infra-user",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["openshift-namespace"]
				}
			}
		}
}

# Test audit access
test_allow_audit_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"audit-policy": mock_audit_policy}}
		with input as {
			"subject": "audit-user",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345"
		}
}

# Test wildcard namespace access
test_allow_wildcard_namespace_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"wildcard-ns-policy": mock_wildcard_ns_policy}}
		with input as {
			"subject": "ns-admin",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["any-namespace-should-work"]
				}
			}
		}
}

# Test wildcard tenant access for application
test_allow_wildcard_tenant_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_multi_permission_policy}}
		with input as {
			"subject": "dev@example.com",
			"groups": ["developers"],
			"resource": "metrics",
			"permission": "read",
			"tenant": "any-tenant-should-work",
			"tenantID": "99999",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["dev"]
				}
			}
		}
}

# Test second permission in the same policy
test_allow_infra_access_from_multi_permission_policy if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_multi_permission_policy}}
		with input as {
			"subject": "dev@example.com",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["default"]
				}
			}
		}
}

# Test write operation
test_allow_write_operation if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_write_policy}}
		with input as {
			"subject": "ok",
			"groups": ["writers"],
			"resource": "logs",
			"permission": "write",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {}
		}
}

# Test write operation with wrong signal should fail
test_allow_write_operation_tenant_only if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_write_infra_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "traces",
			"permission": "write",
			"tenant": "tenant1",
			"tenantID": "12345",
		}
}

# Test write operation with wrong tenant should still fail
test_deny_write_operation_wrong_tenant if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_write_infra_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "write",
			"tenant": "wrong-tenant",
			"tenantID": "12345",
		}
}

# Test alternative namespace field names
test_allow_with_namespace_field if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"namespace": ["test-namespace"]
				}
			}
		}
}

test_allow_with_k8s_namespace_name_field if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			}
		}
}

test_allow_with_no_namespace_for_audit if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"audit-policy": mock_audit_policy}}
		with input as {
			"subject": "audit-user",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"selectors": {}
			}
		}
}
