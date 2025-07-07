package authz

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
