package tracing

import (
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	otelv1alpha1 "github.com/open-telemetry/opentelemetry-operator/apis/v1alpha1"
	operatorsv1 "github.com/operator-framework/api/pkg/operators/v1"
	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/rhobs/multicluster-observability-addon/internal/addon"
	"github.com/rhobs/multicluster-observability-addon/internal/tracing/handlers"
	"github.com/rhobs/multicluster-observability-addon/internal/tracing/manifests"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"open-cluster-management.io/addon-framework/pkg/addonfactory"
	"open-cluster-management.io/addon-framework/pkg/addonmanager/addontesting"
	"open-cluster-management.io/addon-framework/pkg/agent"
	addonapiv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	fakeaddon "open-cluster-management.io/api/client/addon/clientset/versioned/fake"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	_ = otelv1alpha1.AddToScheme(scheme.Scheme)
	_ = operatorsv1.AddToScheme(scheme.Scheme)
	_ = operatorsv1alpha1.AddToScheme(scheme.Scheme)
	_ = certmanagerv1.AddToScheme(scheme.Scheme)
)

func fakeGetValues(k8s client.Client) addonfactory.GetValuesFunc {
	return func(
		cluster *clusterv1.ManagedCluster,
		addon *addonapiv1alpha1.ManagedClusterAddOn,
	) (addonfactory.Values, error) {
		opts, err := handlers.BuildOptions(k8s, addon, nil)
		if err != nil {
			return nil, err
		}

		tracing, err := manifests.BuildValues(opts)
		if err != nil {
			return nil, err
		}

		return addonfactory.JsonStructToValues(tracing)
	}
}

func Test_Tracing_AllConfigsTogether_AllResources(t *testing.T) {
	var (
		// Addon envinronment and registration
		managedCluster      *clusterv1.ManagedCluster
		managedClusterAddOn *addonapiv1alpha1.ManagedClusterAddOn

		// Addon configuration
		addOnDeploymentConfig *addonapiv1alpha1.AddOnDeploymentConfig
		otelCol               *otelv1alpha1.OpenTelemetryCollector
		authCM                *corev1.ConfigMap

		// Test clients
		fakeKubeClient  client.Client
		fakeAddonClient *fakeaddon.Clientset
	)

	// Setup a managed cluster
	managedCluster = addontesting.NewManagedCluster("cluster-1")

	// Register the addon for the managed cluster
	managedClusterAddOn = addontesting.NewAddon("test", "cluster-1")
	managedClusterAddOn.Spec.Configs = []addonapiv1alpha1.AddOnConfig{
		{
			ConfigGroupResource: addonapiv1alpha1.ConfigGroupResource{
				Group:    "",
				Resource: "configmaps",
			},
			ConfigReferent: addonapiv1alpha1.ConfigReferent{
				Namespace: "open-cluster-management",
				Name:      "tracing-auth",
			},
		},
	}
	managedClusterAddOn.Status.ConfigReferences = []addonapiv1alpha1.ConfigReference{
		{
			ConfigGroupResource: addonapiv1alpha1.ConfigGroupResource{
				Group:    "addon.open-cluster-management.io",
				Resource: "addondeploymentconfigs",
			},
			ConfigReferent: addonapiv1alpha1.ConfigReferent{
				Namespace: "open-cluster-management",
				Name:      "multicluster-observability-addon",
			},
		},
		{
			ConfigGroupResource: addonapiv1alpha1.ConfigGroupResource{
				Group:    "opentelemetry.io",
				Resource: "opentelemetrycollectors",
			},
			ConfigReferent: addonapiv1alpha1.ConfigReferent{
				Namespace: "open-cluster-management",
				Name:      "spoke-otelcol",
			},
		},
	}

	// Setup configuration resources: OpenTelemetryCollector, AddOnDeploymentConfig
	b, err := os.ReadFile("./manifests/otelcol/test_data/simplest.yaml")
	require.NoError(t, err)
	otelColConfig := string(b)

	otelCol = &otelv1alpha1.OpenTelemetryCollector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "spoke-otelcol",
			Namespace: "open-cluster-management",
		},
		Spec: otelv1alpha1.OpenTelemetryCollectorSpec{
			Config: otelColConfig,
		},
	}

	addOnDeploymentConfig = &addonapiv1alpha1.AddOnDeploymentConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multicluster-observability-addon",
			Namespace: "open-cluster-management",
		},
		Spec: addonapiv1alpha1.AddOnDeploymentConfigSpec{},
	}

	authCM = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tracing-auth",
			Namespace: "open-cluster-management",
			Labels: map[string]string{
				"mcoa.openshift.io/signal": "tracing",
			},
		},
		Data: map[string]string{
			"otlphttp": "mTLS",
		},
	}

	// This secret will be generated by cert-manager. We need to create it here
	// to mock the behaviour from cert-manager
	generatedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tracing-otlphttp-auth",
			Namespace: "cluster-1",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("data"),
			"ca.crt":  []byte("data"),
			"tls.key": []byte("data"),
		},
	}

	// Setup the fake k8s client
	fakeKubeClient = fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(otelCol, authCM, generatedSecret).
		Build()

	// Setup the fake addon client
	fakeAddonClient = fakeaddon.NewSimpleClientset(addOnDeploymentConfig)
	addonConfigValuesFn := addonfactory.GetAddOnDeploymentConfigValues(
		addonfactory.NewAddOnDeploymentConfigGetter(fakeAddonClient),
		addonfactory.ToAddOnCustomizedVariableValues,
	)

	// Wire everything together to a fake addon instance
	tracingAgentAddon, err := addonfactory.NewAgentAddonFactory(addon.Name, addon.FS, addon.TracingChartDir).
		WithGetValuesFuncs(addonConfigValuesFn, fakeGetValues(fakeKubeClient)).
		WithAgentRegistrationOption(&agent.RegistrationOption{}).
		WithScheme(scheme.Scheme).
		BuildHelmAgentAddon()
	if err != nil {
		klog.Fatalf("failed to build agent %v", err)
	}

	// Render manifests and return them as k8s runtime objects
	objects, err := tracingAgentAddon.Manifests(managedCluster, managedClusterAddOn)
	require.NoError(t, err)
	require.Equal(t, 5, len(objects))

	for _, obj := range objects {
		switch obj := obj.(type) {
		case *otelv1alpha1.OpenTelemetryCollector:
			require.Equal(t, "spoke-otelcol", obj.ObjectMeta.Name)
			require.Equal(t, "spoke-otelcol", obj.ObjectMeta.Namespace)
			require.NotEmpty(t, obj.Spec.Config)
		case *corev1.Secret:
			if obj.Name == "tracing-otlphttp-auth" {
				require.Equal(t, generatedSecret.Data, obj.Data)
			}
		}
	}
}
