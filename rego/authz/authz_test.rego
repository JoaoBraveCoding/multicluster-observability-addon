package authz_test

import data.authz

# Test data setup
mock_policy := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"tenants": ["tenant1"],
		"namespaces": ["test-namespace"],
		"signals": ["metrics"],
		"permission": ["read"],
	}],
}}

mock_policy_with_write := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"tenants": ["tenant1"],
		"signals": ["metrics"],
		"permission": ["write"],
	}],
}}

mock_policy_wildcard_ns := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"tenants": ["tenant1"],
		"namespaces": ["*"],
		"signals": ["metrics"],
		"permission": ["read"],
	}],
}}

mock_policy_infra_ns := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"tenants": ["tenant1"],
		"namespaces": ["openshift-monitoring"],
		"signals": ["metrics"],
		"permission": ["read"],
	}],
}}

mock_policy_multi_permission := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [
		{
			"tenants": ["*"],
			"namespaces": ["dev", "staging"],
			"signals": ["metrics", "traces"],
			"permission": ["read"],
		},
		{
			"resourceScope": "infrastructure",
			"tenants": ["tenant3"],
			"signals": ["logs"],
			"permission": ["read"],
		},
	],
}}

mock_policy_logs := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"resourceScope": "application",
		"tenants": ["tenant1"],
		"namespaces": ["test-namespace"],
		"signals": ["logs"],
		"permission": ["read"],
	}],
}}

mock_policy_logs_infra := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"resourceScope": "infrastructure",
		"tenants": ["tenant1"],
		"signals": ["logs"],
		"permission": ["read"],
	}],
}}

mock_policy_logs_audit := {"spec": {
	"subjects": [
		{"kind": "User", "name": "alice"},
		{"kind": "Group", "name": "admins"},
	],
	"accessRules": [{
		"resourceScope": "audit",
		"tenants": ["tenant1"],
		"signals": ["logs"],
		"permission": ["read"],
	}],
}}

# Test deny wildcard selectors
test_deny_wildcardSelectors if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {
				"selectors": {"k8s_namespace_name": ["open.*"]},
				"wildcardSelectors": true,
			},
		}
}

# Test write with missing permissions
test_deny_missing_write_permissions if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "write",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test write with correct permissions
test_allow_write_with_correct_permissions if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_with_write}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "write",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

test_deny_with_only_write_permissions if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_with_write}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test denying an invalid user
test_deny_invalid_user if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "bob",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test denying an invalid group
test_deny_invalid_group if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "",
			"groups": ["invalid-group"],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
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
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test allow group membership
test_allow_group_member if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "charlie",
			"groups": ["admins"],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test deny access to the wrong tenant
test_deny_wrong_tenant if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant2",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test deny access to the wrong signal
test_deny_wrong_signal if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
}

# Test deny access to the wrong namespace
test_deny_wrong_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["eve-namespace"]}},
		}
}

# Test deny access missing namespace
test_deny_missing_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {},
		}
}

# Test wildcard namespace access
test_allow_wildcard_namespace_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"wildcard-ns-policy": mock_policy_wildcard_ns}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["any-namespace-should-work"]}},
		}
}

# Test access openshift namespace access
test_allow_openshift_namespace_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_infra_ns}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["openshift-monitoring"]}},
		}
}

# Test access to namespace with missing access
test_deny_missing_namespace_access if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_infra_ns}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["openshift-monitoring", "test-namespace"]}},
		}
}

test_allow_namespace_access_multi_permission_policy if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_policy_multi_permission}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant2",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["dev"]}},
		}
}

test_allow_log_namespace_access_multi_permission_policy if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_policy_multi_permission}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant3",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-monitoring"],
				"type": ["infrastructure"],
			}},
		}
}

test_deny_log_namespace_access_multi_permission_policy if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"multi-perm-policy": mock_policy_multi_permission}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant3",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["dev"],
				"type": ["application"],
			}},
		}
}

# Test allow metadataOnly query without namespace
test_allow_metadata_no_namespace if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"metadataOnly": true},
		}
}

# Test allow metadataOnly query with namespace
test_allow_metadata_with_namespace if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"metadataOnly": true,
				"selectors": {"k8s_namespace_name": ["test-namespace"]},
			},
		}
}

# Test allow metadataOnly query with wildcard permission namespace
test_allow_metadata_with_wildcard if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_wildcard_ns}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"metadataOnly": true,
				"selectors": {"k8s_namespace_name": ["any-namespace-should-work"]},
			},
		}
}

# Test deny metadataOnly query with namespace the user is not allowed to access
test_deny_metadata_with_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"metadataOnly": true,
				"selectors": {"k8s_namespace_name": ["eve-namespace"]},
			},
		}
}

# ----------------------------
# ----- Log Access Tests -----
# ----------------------------

# Test allow logs access
test_allow_logs_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["test-namespace"],
				"type": ["application"],
			}},
		}
}

# Test deny logs access with wrong namespace
test_deny_logs_access_wrong_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["eve-namespace"],
				"type": ["application"],
			}},
		}
}

# Test deny logs access infra namespace with missing type label
test_deny_logs_infra_access_missing_label if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["openshift-namespace"]}},
		}
}

# Test deny logs access infra namespace with wrong authorization scope
test_deny_logs_infra_access_missing_permission if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-namespace"],
				"type": ["infrastructure"],
			}},
		}
}

# Test deny logs access infra namespace with wrong scope
test_deny_logs_infra_access_wrong_scope if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-namespace"],
				"type": ["application"],
			}},
		}
}

# Test infra access
test_allow_logs_infra_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs_infra}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-namespace"],
				"type": ["infrastructure"],
			}},
		}
}

# Test deny access wrong namespace for infra access
test_deny_logs_infra_access_wrong_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs_infra}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-namespace", "test-namespace"],
				"type": ["infrastructure"],
			}},
		}
}

# Test allow metadataOnly query without namespace
test_allow_logs_metadata_no_namespace if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"metadataOnly": true},
		}
}

# Test deny logs metadata query with namespace but missing type
test_deny_logs_metadata_valid_namespace_missing_type if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"metadataOnly": true,
				"selectors": {
					"k8s_namespace_name": ["test-namespace"]
				}
			},
		}
}

# Test deny logs metadata query with forbiden namespace
test_deny_logs_metadata_wrong_namespace if {
	not authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy_logs}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {
				"metadataOnly": true,
				"selectors": {
					"k8s_namespace_name": ["eve-namespace"],
					"type": ["application"],
				}
			},
		}
}

# Test audit access
test_allow_audit_access if {
	authz.allow with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"audit-policy": mock_policy_logs_audit}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"type": ["audit"]}},
		}
}

# ----------------------------------
# ----- Deny Message Tests -----
# ----------------------------------

test_message_deny_wildcardSelectors if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {
				"selectors": {"k8s_namespace_name": ["open.*"]},
				"wildcardSelectors": true,
			},
		}
	count(deny) == 1
	"Access Denied: Your user query contains wildcard selectors which are currently unsupported.", true in deny
}

test_message_deny_invalid_user if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "bob",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
	count(deny) == 1
	"Access Denied: Your user 'bob' or groups '[]' are not configured in any ObservabilityAccessPolicies in the hub cluster.", true in deny
}

test_message_deny_wrong_tenant if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant2",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
	count(deny) == 1
	"Access Denied: You do not have permission for the tenant 'tenant2'.", true in deny
}

test_message_deny_wrong_signal if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
	count(deny) == 1
	"Access Denied: You do not have permission 'read' to access the signal 'logs' for the tenant 'tenant1'.", true in deny
}

test_message_deny_wrong_namespace if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["eve-namespace"]}},
		}
	count(deny) == 1
	"Access Denied: Your 'metrics' query for the tenant 'tenant1' using the scope 'application' contains the following namespaces that are not allowed to be queried: {\"eve-namespace\"}.", true in deny
}

test_message_deny_missing_namespace if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {},
		}
	count(deny) == 1
	"Access Denied: Your 'metrics' query for the tenant 'tenant1' using the scope 'application' does not specify any namespaces to query.", true in deny
}

test_message_deny_missing_write_permissions if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"test-policy": mock_policy}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "metrics",
			"permission": "write",
			"tenant": "tenant1",
			"tenantID": "67890",
			"extras": {"selectors": {"k8s_namespace_name": ["test-namespace"]}},
		}
	count(deny) == 1
	"Access Denied: You do not have permission 'write' to access the signal 'metrics' for the tenant 'tenant1'.", true in deny
}

test_message_deny_infra_access_wrong_namespace if {
	deny := authz.deny with data.kubernetes.observabilityaccesspolicies as {"test-namespace": {"infra-policy": mock_policy_logs_infra}}
		with input as {
			"subject": "alice",
			"groups": [],
			"resource": "logs",
			"permission": "read",
			"tenant": "tenant1",
			"tenantID": "12345",
			"extras": {"selectors": {
				"k8s_namespace_name": ["openshift-namespace", "test-namespace"],
				"type": ["infrastructure"],
			}},
		}
	count(deny) == 1
	"Access Denied: Your log query for the tenant 'tenant1' contains the following namespaces that are not allowed for the scope 'infrastructure': {\"test-namespace\"}.", true in deny
}
