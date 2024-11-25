package addon

import (
	"errors"
	"fmt"

	otelv1alpha1 "github.com/open-telemetry/opentelemetry-operator/apis/v1alpha1"
	loggingv1 "github.com/openshift/cluster-logging-operator/api/observability/v1"
	"open-cluster-management.io/addon-framework/pkg/agent"
	"open-cluster-management.io/addon-framework/pkg/utils"
	addonapiv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	workv1 "open-cluster-management.io/api/work/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	errMissingFields              = errors.New("no fields found in health checker")
	errProbeConditionNotSatisfied = errors.New("probe condition is not satisfied")
	errProbeValueIsNil            = errors.New("probe value is nil")
	errUnknownProbeKey            = errors.New("probe has key that doesn't match the key defined")
	errUnknownResource            = errors.New("undefined health check for resource")
)

func NewRegistrationOption(agentName string) *agent.RegistrationOption {
	return &agent.RegistrationOption{
		CSRConfigurations: agent.KubeClientSignerConfigurations(Name, agentName),
		CSRApproveCheck:   utils.DefaultCSRApprover(agentName),
	}
}

func GetObjectKeys(configRef []addonapiv1alpha1.ConfigReference, group, resource string) []client.ObjectKey {
	var keys []client.ObjectKey
	for _, config := range configRef {
		if config.ConfigGroupResource.Group != group {
			continue
		}
		if config.ConfigGroupResource.Resource != resource {
			continue
		}

		keys = append(keys, client.ObjectKey{
			Name:      config.Name,
			Namespace: config.Namespace,
		})
	}
	return keys
}

// AgentHealthProber returns a HealthProber struct that contains the necessary
// information to assert if an addon deployment is ready or not.
func AgentHealthProber() *agent.HealthProber {
	return &agent.HealthProber{
		Type: agent.HealthProberTypeWork,
		WorkProber: &agent.WorkHealthProber{
			ProbeFields: []agent.ProbeField{
				{
					ResourceIdentifier: workv1.ResourceIdentifier{
						Group:     loggingv1.GroupVersion.Group,
						Resource:  ClusterLogForwardersResource,
						Name:      SpokeCLFName,
						Namespace: SpokeCLFNamespace,
					},
					ProbeRules: []workv1.FeedbackRule{
						{
							Type: workv1.JSONPathsType,
							JsonPaths: []workv1.JsonPath{
								{
									Name: clfProbeKey,
									Path: clfProbePath,
								},
							},
						},
					},
				},
				{
					ResourceIdentifier: workv1.ResourceIdentifier{
						Group:     otelv1alpha1.GroupVersion.Group,
						Resource:  OpenTelemetryCollectorsResource,
						Name:      SpokeOTELColName,
						Namespace: SpokeOTELColNamespace,
					},
					ProbeRules: []workv1.FeedbackRule{
						{
							Type: workv1.JSONPathsType,
							JsonPaths: []workv1.JsonPath{
								{
									Name: otelColProbeKey,
									Path: otelColProbePath,
								},
							},
						},
					},
				},
			},
			HealthChecker: func(fields []agent.ResultField) error {
				if len(fields) == 0 {
					return errMissingFields
				}
				for _, field := range fields {
					if len(field.FeedbackResult.Values) == 0 {
						// If a probe didn't get any values maybe the resources was not deployed
						continue
					}
					identifier := field.ResourceIdentifier
					switch {
					case identifier.Resource == ClusterLogForwardersResource:
						for _, value := range field.FeedbackResult.Values {
							if value.Name != clfProbeKey {
								return fmt.Errorf("%w: %s with key %s/%s unknown probe keys %s", errUnknownProbeKey, identifier.Resource, identifier.Namespace, identifier.Name, value.Name)
							}

							if value.Value.String == nil {
								return fmt.Errorf("%w: %s with key %s/%s", errProbeValueIsNil, identifier.Resource, identifier.Namespace, identifier.Name)
							}

							if *value.Value.String != "True" {
								return fmt.Errorf("%w: %s status condition type is %s for %s/%s", errProbeConditionNotSatisfied, identifier.Resource, *value.Value.String, identifier.Namespace, identifier.Name)
							}
							// everything checks we should skip to the next field
						}
					case identifier.Resource == OpenTelemetryCollectorsResource:
						for _, value := range field.FeedbackResult.Values {
							if value.Name != otelColProbeKey {
								return fmt.Errorf("%w: %s with key %s/%s unknown probe keys %s", errUnknownProbeKey, identifier.Resource, identifier.Namespace, identifier.Name, value.Name)
							}

							if value.Value.Integer == nil {
								return fmt.Errorf("%w: %s with key %s/%s", errProbeValueIsNil, identifier.Resource, identifier.Namespace, identifier.Name)
							}

							if *value.Value.Integer < 1 {
								return fmt.Errorf("%w: %s replicas is %d for %s/%s", errProbeConditionNotSatisfied, identifier.Resource, *value.Value.Integer, identifier.Namespace, identifier.Name)
							}
							// everything checks we should skip to the next field
						}
					default:
						// If a resource is being probed it should have a health check defined
						return fmt.Errorf("%w: %s with key %s/%s", errUnknownResource, identifier.Resource, identifier.Namespace, identifier.Name)
					}
				}
				return nil
			},
		},
	}
}
