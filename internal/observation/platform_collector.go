package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// PlatformRawGetter exposes only the exact Application GETs selected when the
// adapter is constructed.
type PlatformRawGetter interface {
	Get(context.Context, string) ([]byte, error)
}

// PlatformCapabilitySource returns one already verified, redaction-safe
// capability assertion. It intentionally cannot accept a command or execute a
// test from this Argo adapter.
type PlatformCapabilitySource interface {
	Capability(context.Context) (PlatformCapabilityState, error)
}

type PlatformCollectorConfig struct {
	Profile          PlatformProfile
	TargetClusterUID string
	Clock            func() time.Time
}

type PlatformSourceCollector struct {
	argo       PlatformRawGetter
	capability PlatformCapabilitySource
	config     PlatformCollectorConfig
}

func NewPlatformSourceCollector(argo PlatformRawGetter, capability PlatformCapabilitySource, config PlatformCollectorConfig) (*PlatformSourceCollector, error) {
	if argo == nil || capability == nil || config.Clock == nil {
		return nil, errors.New("platform collector sources and clock are required")
	}
	if err := ValidatePlatformProfile(config.Profile); err != nil || !validUID(config.TargetClusterUID) {
		return nil, errors.New("platform collector profile is invalid")
	}
	return &PlatformSourceCollector{argo: argo, capability: capability, config: config}, nil
}

func (collector *PlatformSourceCollector) Observe(ctx context.Context, policy Policy) (Evidence, error) {
	applicationSnapshot, err := collector.collectApplications(ctx, policy)
	if err != nil {
		return Evidence{}, err
	}
	gate, err := EvaluatePlatformApplications(policy, collector.config.Profile, applicationSnapshot)
	if err != nil {
		return Evidence{}, err
	}
	if gate.Status != "True" {
		return gate, nil
	}
	snapshot, err := collector.collectCapability(ctx, applicationSnapshot)
	if err != nil {
		return Evidence{}, err
	}
	return EvaluatePlatformSnapshot(policy, collector.config.Profile, snapshot)
}

// Collect performs exactly one GET per profiled Application plus one bounded
// capability-source read. It has no list, discovery, watch, mutation, sync,
// retry, repair, target-cluster access or arbitrary-command path.
func (collector *PlatformSourceCollector) Collect(ctx context.Context, policy Policy) (PlatformSnapshot, error) {
	applicationSnapshot, err := collector.collectApplications(ctx, policy)
	if err != nil {
		return PlatformSnapshot{}, err
	}
	gate, err := EvaluatePlatformApplications(policy, collector.config.Profile, applicationSnapshot)
	if err != nil {
		return PlatformSnapshot{}, err
	}
	if gate.Status != "True" {
		return PlatformSnapshot{}, errors.New("platform Applications are not current; capability execution is closed")
	}
	return collector.collectCapability(ctx, applicationSnapshot)
}

func (collector *PlatformSourceCollector) collectApplications(ctx context.Context, policy Policy) (PlatformApplicationSnapshot, error) {
	if err := validatePolicy(policy, true); err != nil {
		return PlatformApplicationSnapshot{}, err
	}
	if err := validatePlatformProfile(policy, collector.config.Profile); err != nil {
		return PlatformApplicationSnapshot{}, err
	}
	if collector.config.TargetClusterUID != policy.TargetClusterUID {
		return PlatformApplicationSnapshot{}, errors.New("platform collector target differs from the runtime-bound Cluster")
	}
	applications := make([]PlatformApplicationState, 0, len(collector.config.Profile.RequiredApplications))
	for _, expected := range collector.config.Profile.RequiredApplications {
		path := platformApplicationPath(collector.config.Profile.ArgoNamespace, expected.Name)
		object, err := getPlatformObject(ctx, collector.argo, path)
		if err != nil {
			return PlatformApplicationSnapshot{}, fmt.Errorf("collect exact Argo Application: %w", err)
		}
		application, err := normalizePlatformApplication(object, collector.config.Profile, expected)
		if err != nil {
			return PlatformApplicationSnapshot{}, err
		}
		applications = append(applications, application)
	}
	sortPlatformApplications(applications)
	return PlatformApplicationSnapshot{
		Format: PlatformApplicationSnapshotFormat, ObservedAt: collector.config.Clock().UTC().Format(time.RFC3339Nano),
		TargetClusterUID: collector.config.TargetClusterUID, Applications: applications,
	}, nil
}

func (collector *PlatformSourceCollector) collectCapability(ctx context.Context, applicationSnapshot PlatformApplicationSnapshot) (PlatformSnapshot, error) {
	capability, err := collector.capability.Capability(ctx)
	if err != nil {
		return PlatformSnapshot{}, errors.New("collect bounded platform capability evidence")
	}
	return PlatformSnapshot{
		Format: PlatformSnapshotFormat, ObservedAt: collector.config.Clock().UTC().Format(time.RFC3339Nano),
		TargetClusterUID: applicationSnapshot.TargetClusterUID,
		Applications:     applicationSnapshot.Applications, Capability: capability,
	}, nil
}

func getPlatformObject(ctx context.Context, source PlatformRawGetter, path string) (map[string]any, error) {
	raw, err := source.Get(ctx, path)
	if err != nil {
		return nil, errors.New("bounded platform source GET failed")
	}
	if len(raw) == 0 || len(raw) > maximumPlatformSourceBytes {
		return nil, errors.New("platform source response size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("platform source returned invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("platform source returned trailing JSON")
	}
	return value, nil
}

func normalizePlatformApplication(object map[string]any, profile PlatformProfile, expected PlatformApplicationExpectation) (PlatformApplicationState, error) {
	if text(object["apiVersion"]) != "argoproj.io/v1alpha1" || text(object["kind"]) != "Application" {
		return PlatformApplicationState{}, errors.New("Argo Application API identity is invalid")
	}
	metadata, err := objectMap(object, "metadata")
	if err != nil || text(metadata["namespace"]) != profile.ArgoNamespace || text(metadata["name"]) != expected.Name {
		return PlatformApplicationState{}, errors.New("Argo Application object identity differs from exact target")
	}
	uid, resourceVersion := text(metadata["uid"]), text(metadata["resourceVersion"])
	if !validUID(uid) || resourceVersion == "" {
		return PlatformApplicationState{}, errors.New("Argo Application runtime identity is invalid")
	}
	annotations, _ := objectMap(metadata, "annotations")
	spec, err := objectMap(object, "spec")
	if err != nil {
		return PlatformApplicationState{}, errors.New("Argo Application spec is missing")
	}
	normalizedSpec, _, err := normalizedPlatformApplicationSpec(spec)
	if err != nil {
		return PlatformApplicationState{}, err
	}
	destination, _ := normalizedSpec["destination"].(map[string]any)
	if text(destination["name"]) != profile.RegistrationName {
		return PlatformApplicationState{}, errors.New("Argo Application destination differs from the bound registration")
	}
	specDigest, desiredRevision, err := PlatformApplicationSpecIdentity(spec)
	if err != nil {
		return PlatformApplicationState{}, err
	}
	status, _ := objectMap(object, "status")
	sync, _ := objectMap(status, "sync")
	health, _ := objectMap(status, "health")
	return PlatformApplicationState{
		Name: expected.Name, UID: uid, ResourceVersion: resourceVersion,
		IntentRevision:   text(annotations["openkubes.io/intent-revision"]),
		PlatformRevision: text(annotations["openkubes.io/platform-revision"]),
		ExecutionFixture: text(annotations["openkubes.io/execution-fixture"]),
		SpecDigest:       specDigest, DesiredSourceRevision: desiredRevision,
		AppliedSourceRevision: text(sync["revision"]), SyncStatus: text(sync["status"]), HealthStatus: text(health["status"]),
	}, nil
}

func normalizedPlatformApplicationSpec(spec map[string]any) (map[string]any, string, error) {
	source, err := objectMap(spec, "source")
	if err != nil {
		return nil, "", errors.New("Argo Application source is missing")
	}
	destination, err := objectMap(spec, "destination")
	if err != nil {
		return nil, "", errors.New("Argo Application destination is missing")
	}
	revision := text(source["targetRevision"])
	if !validGitCommit(revision) || text(source["repoURL"]) == "" || text(source["path"]) == "" || text(spec["project"]) == "" || text(destination["name"]) == "" || text(destination["namespace"]) == "" {
		return nil, "", errors.New("Argo Application semantic identity is incomplete or mutable")
	}
	// Argo's API representation may omit directory.recurse=false even when the
	// submitted desired object spells the default explicitly. Bind the semantic
	// default so the desired and observed forms retain one identity.
	normalizedSource := make(map[string]any, len(source))
	for key, value := range source {
		normalizedSource[key] = value
	}
	if directory, ok := source["directory"].(map[string]any); ok {
		normalizedDirectory := make(map[string]any, len(directory)+1)
		for key, value := range directory {
			normalizedDirectory[key] = value
		}
		if _, present := normalizedDirectory["recurse"]; !present {
			normalizedDirectory["recurse"] = false
		}
		normalizedSource["directory"] = normalizedDirectory
	}
	// Keep all source and sync semantics, but only the stable target fields. The
	// API may default unrelated destination fields; these cannot change P.
	normalized := map[string]any{
		"project":     spec["project"],
		"source":      normalizedSource,
		"destination": map[string]any{"name": destination["name"], "namespace": destination["namespace"]},
	}
	if syncPolicy, exists := spec["syncPolicy"]; exists {
		normalized["syncPolicy"] = syncPolicy
	}
	if ignoreDifferences, exists := spec["ignoreDifferences"]; exists {
		normalized["ignoreDifferences"] = ignoreDifferences
	}
	return normalized, revision, nil
}

// PlatformApplicationSpecIdentity is the shared semantic identity used by
// both the externally rendered Application verifier and the later read-only
// Argo observer. It prevents a second, drifting definition of applied P.
func PlatformApplicationSpecIdentity(spec map[string]any) (string, string, error) {
	normalized, revision, err := normalizedPlatformApplicationSpec(spec)
	if err != nil {
		return "", "", err
	}
	specDigest, err := canonicalDigest(normalized)
	if err != nil {
		return "", "", errors.New("digest normalized Argo Application spec")
	}
	return specDigest, revision, nil
}

func validGitCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
