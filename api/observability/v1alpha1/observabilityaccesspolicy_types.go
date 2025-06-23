package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SubjectKind defines the kind of subject that can be granted permissions.
// +kubebuilder:validation:Enum=User;Group
type SubjectKind string

const (
	UserKind  SubjectKind = "User"
	GroupKind SubjectKind = "Group"
)

// ResourceScope defines the scope of the observability data.
// +kubebuilder:validation:Enum=application;infrastructure;audit
type ResourceScope string

const (
	ApplicationScope    ResourceScope = "application" // Default
	InfrastructureScope ResourceScope = "infrastructure"
	AuditScope          ResourceScope = "audit"
)

// SignalType defines the type of observability signal.
// +kubebuilder:validation:Enum=metrics;logs;traces;k8s_audit_events
type SignalType string

const (
	MetricsSignal        SignalType = "metrics"
	LogsSignal           SignalType = "logs"
	TracesSignal         SignalType = "traces"
	K8sAuditEventsSignal SignalType = "k8s_audit_events" // Specific for audit scope if needed
)

// AccessLevelType defines the level of access.
// +kubebuilder:validation:Enum=read
type AccessLevelType string

const (
	ReadAccess AccessLevelType = "read" // Default
)

// Subject represents a user, group, or service account that can be granted permissions.
type Subject struct {
	// Kind of the subject (User or Group).
	// +kubebuilder:validation:Required
	Kind SubjectKind `json:"kind"`

	// Name of the subject.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// APIGroup is the API group of the subject.
	// Defaults to "rbac.authorization.k8s.io" if not specified for Kind Group.
	// +kubebuilder:default="rbac.authorization.k8s.io"
	APIGroup string `json:"apiGroup,omitempty"`
}

// PermissionRule defines a specific set of permissions.
type PermissionRule struct {
	// ResourceScope defines the scope of the observability data this permission applies to.
	// Defaults to "application".
	// +kubebuilder:default=application
	ResourceScope ResourceScope `json:"resourceScope,omitempty"`

	// Tenants is a list of tenant IDs this permission rule applies to.
	// Required for all scopes: 'application', 'infrastructure', and 'audit'.
	// Can use "*" for all tenants (use with caution, interpretation handled by OPA policy).
	// +kubebuilder:validation:MinItems=1
	Tenants []string `json:"tenants"` // Made non-omitempty as it's generally required per rule.

	// Namespaces is a list of Kubernetes namespaces.
	// Only applicable and used when resourceScope is "application".
	// If omitted or empty for 'application' scope, implies all namespaces in the specified tenants for this rule.
	Namespaces []string `json:"namespaces,omitempty"`

	// ApplicationSignals lists the allowed signal types (metrics, logs, traces) for the 'application' scope.
	// Only applicable if resourceScope is "application".
	ApplicationSignals []SignalType `json:"applicationSignals,omitempty"`

	// InfrastructureSignals lists the allowed signal types (metrics, logs, traces) for the 'infrastructure' scope.
	// Only applicable if resourceScope is "infrastructure".
	InfrastructureSignals []SignalType `json:"infrastructureSignals,omitempty"`

	// AuditSignals lists the allowed signal types (typically logs or k8s_audit_events) for the 'audit' scope.
	// Only applicable if resourceScope is "audit".
	AuditSignals []SignalType `json:"auditSignals,omitempty"`

	// AccessLevel defines the level of access granted.
	// Defaults to "read".
	// +kubebuilder:default=read
	AccessLevel AccessLevelType `json:"accessLevel,omitempty"`
}

// ObservabilityAccessPolicySpec defines the desired state of ObservabilityAccessPolicy.
type ObservabilityAccessPolicySpec struct {
	// Subjects is a list of users, groups, or service accounts this policy applies to.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Subjects []Subject `json:"subjects"`

	// Permissions is a list of permission rules granting access.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Permissions []PermissionRule `json:"permissions"`
}

// ObservabilityAccessPolicyStatus defines the observed state of ObservabilityAccessPolicy.
type ObservabilityAccessPolicyStatus struct {
	// Conditions of the access policy.
	//
	// +operator-sdk:csv:customresourcedefinitions:type=status,displayName="Forwarder Conditions",xDescriptors={"urn:alm:descriptor:io.kubernetes.conditions"}
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ObservabilityAccessPolicy is the Schema for the observabilityaccesspolicies API
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=observability,shortName=oap
// +kubebuilder:validation:XValidation:rule="self.metadata.name.matches('^[a-z][a-z0-9-]{1,61}[a-z0-9]$')",message="Name must be a valid DNS1035 label"
type ObservabilityAccessPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ObservabilityAccessPolicySpec   `json:"spec,omitempty"`
	Status ObservabilityAccessPolicyStatus `json:"status,omitempty"`
}

// ObservabilityAccessPolicyList contains a list of ObservabilityAccessPolicy
//
// +kubebuilder:object:root=true
type ObservabilityAccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ObservabilityAccessPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ObservabilityAccessPolicy{}, &ObservabilityAccessPolicyList{})
}
