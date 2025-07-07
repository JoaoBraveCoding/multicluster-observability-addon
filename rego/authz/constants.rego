package authz

_log_signal := "logs"

_read_permission := "read"

_application_scope := "application"
_infrastructure_scope := "infrastructure"

_rule_tenants_key := "tenants"
_rule_signals_key := "signals"
_rule_namespaces_key := "namespaces"
_rule_scope_key := "resourceScope"
_rule_permission_key := "permission"

_request_selectors_key := "selectors"
_request_metadata_key := "metadataOnly"
_request_wildcard_selectors_key := "wildcardSelectors"
_request_namespace_label_key := "k8s_namespace_name"
_request_log_type_label_key := "log_type"

_unauthorized_wildcard_selectors := "Access Denied: Your user query contains wildcard selectors which are currently unsupported."
_missing_policies_deny_message := "Access Denied: Your user '%s' or groups '%s' are not configured in any ObservabilityAccessPolicies in the hub cluster."
_unauthorized_tenant_message := "Access Denied: You do not have permission for the tenant '%s'."
_missing_type_label := "Access Denied: To query logs you need to provide the label \"log_type\" with either \"application\", \"infrastructure\" or \"audit\"."
_missing_signal_permissions_for_tenant := "Access Denied: You do not have permission '%s' to access the signal '%s' for the tenant '%s'."
_missing_query_permissions_for_tenant := "Access Denied: You do not have permission to query the signal '%s' using the scope '%s' for the tenant '%s'."
_forbidden_namespaces_in_scope := "Access Denied: Your log query for the tenant '%s' contains the following namespaces that are not allowed for the scope '%s': %s."
_forbidden_namespaces := "Access Denied: Your '%s' query for the tenant '%s' using the scope '%s' contains the following namespaces that are not allowed to be queried: %s."
_missing_namespaces := "Access Denied: Your '%s' query for the tenant '%s' using the scope '%s' does not specify any namespaces to query."
