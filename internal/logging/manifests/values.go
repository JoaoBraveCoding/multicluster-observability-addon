package manifests

import (
	"encoding/json"
)

type LoggingValues struct {
	Enabled                 bool            `json:"enabled"`
	OpenshiftLoggingChannel string          `json:"openshiftLoggingChannel"`
	Unmanaged               UnmanagedValues `json:"unmanaged"`
	Managed                 ManagedValues   `json:"managed"`
}

// UnmanagedValues is a struct that holds configuration for resources managed by
// the user.
type UnmanagedValues struct {
	Collection CollectionValues `json:"collection"`
}

// ManagedValues is a struct that holds configuration for resources managed by
// MCOA.
type ManagedValues struct {
	Collection CollectionValues `json:"collection"`
	Storage    StorageValues    `json:"storage"`
}

type CollectionValues struct {
	Enabled        bool            `json:"enabled"`
	CLFAnnotations string          `json:"clfAnnotations"`
	CLFSpec        string          `json:"clfSpec"`
	Secrets        []ResourceValue `json:"secrets"`
	ConfigMaps     []ResourceValue `json:"configmaps"`
}

type StorageValues struct {
	Enabled bool            `json:"enabled"`
	Secrets []ResourceValue `json:"secrets"`
	LSSpec  string          `json:"lsSpec"`
}

type ResourceValue struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

func BuildValues(opts Options) (*LoggingValues, error) {
	uValues, err := buildUnmangedValues(opts)
	if err != nil {
		return nil, err
	}

	mValues, err := buildMangedValues(opts)
	if err != nil {
		return nil, err
	}

	return &LoggingValues{
		Enabled:                 enabledLogging(opts),
		OpenshiftLoggingChannel: buildSubscriptionChannel(opts),
		Unmanaged:               uValues,
		Managed:                 mValues,
	}, nil
}

func enabledLogging(opts Options) bool {
	return opts.UnmanagedCollectionEnabled() || opts.DefaultStackEnabled()
}

func buildUnmangedValues(opts Options) (UnmanagedValues, error) {
	if !opts.UnmanagedCollectionEnabled() {
		return UnmanagedValues{}, nil
	}

	uValues := UnmanagedValues{
		Collection: CollectionValues{
			Enabled: true,
		},
	}

	configmaps, err := buildConfigMaps(opts)
	if err != nil {
		return uValues, err
	}
	uValues.Collection.ConfigMaps = configmaps

	secrets, err := buildSecrets(opts)
	if err != nil {
		return uValues, err
	}
	uValues.Collection.Secrets = secrets

	// CLO uses annotations to signal feature flags so users must be able to set
	// them
	clfAnnotations := opts.Unmanaged.Collection.ClusterLogForwarder.GetAnnotations()
	clfAnnotationsJson, err := json.Marshal(clfAnnotations)
	if err != nil {
		return uValues, err
	}
	uValues.Collection.CLFAnnotations = string(clfAnnotationsJson)

	clfSpec, err := buildClusterLogForwarderSpec(opts)
	if err != nil {
		return uValues, err
	}

	b, err := json.Marshal(clfSpec)
	if err != nil {
		return uValues, err
	}
	uValues.Collection.CLFSpec = string(b)

	return uValues, nil
}

func buildMangedValues(opts Options) (ManagedValues, error) {
	if !opts.DefaultStackEnabled() {
		return ManagedValues{}, nil
	}
	mValues := ManagedValues{}

	if !opts.IsHubCluster {
		mValues.Collection = CollectionValues{
			Enabled: true,
		}
		configmaps, err := buildManagedCollectionConfigMaps(opts)
		if err != nil {
			return mValues, err
		}
		mValues.Collection.ConfigMaps = configmaps

		secrets, err := buildManagedCollectionSecrets(opts)
		if err != nil {
			return mValues, err
		}
		mValues.Collection.Secrets = secrets

		clfSpec, err := buildManagedCLFSpec(opts)
		if err != nil {
			return mValues, err
		}

		clfMarshaled, err := json.Marshal(clfSpec)
		if err != nil {
			return mValues, err
		}
		mValues.Collection.CLFSpec = string(clfMarshaled)
	}

	if opts.IsHubCluster {
		mValues.Storage = StorageValues{
			Enabled: true,
		}
		secrets, err := buildManagedStorageSecrets(opts)
		if err != nil {
			return mValues, err
		}
		mValues.Storage.Secrets = secrets

		lsSpec, err := buildManagedLokistackSpec(opts)
		if err != nil {
			return mValues, err
		}

		lsMarshaled, err := json.Marshal(lsSpec)
		if err != nil {
			return mValues, err
		}
		mValues.Storage.LSSpec = string(lsMarshaled)
	}

	return mValues, nil
}
