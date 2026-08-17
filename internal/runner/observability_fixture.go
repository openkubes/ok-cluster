package runner

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const ObservabilitySyntheticFixtureFormat = "ok147-observability-synthetic-fixture/v1"

var capabilityImageDigestPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`)

type ObservabilitySyntheticFixtureConfig struct {
	PushgatewayImage string
	LogEmitterImage  string
}

type CapabilityObjectIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// CapabilityObject is one exact generated object. No caller-supplied raw
// manifest or REST path enters this type.
type CapabilityObject struct {
	Identity       CapabilityObjectIdentity `json:"identity"`
	Digest         string                   `json:"digest"`
	CollectionPath string                   `json:"collectionPath"`
	ObjectPath     string                   `json:"objectPath"`
	Raw            json.RawMessage          `json:"-"`
}

type ObservabilitySyntheticFixture struct {
	Format             string             `json:"format"`
	RunID              string             `json:"runId"`
	Namespace          string             `json:"namespace"`
	MetricsWorkload    string             `json:"metricsWorkload"`
	LogEmitter         string             `json:"logEmitter"`
	MetricName         string             `json:"metricName"`
	AlertTriggerMetric string             `json:"alertTriggerMetric"`
	LogMarker          string             `json:"logMarker"`
	Objects            []CapabilityObject `json:"objects"`
	FixtureDigest      string             `json:"fixtureDigest"`
}

// BuildObservabilitySyntheticFixture is the only manifest constructor for the
// capability transport. It produces exactly Deployment, Service,
// ServiceMonitor and log-emitter Pod objects in fixed order.
func BuildObservabilitySyntheticFixture(run ObservabilityCapabilityRun, config ObservabilitySyntheticFixtureConfig) (ObservabilitySyntheticFixture, error) {
	if err := validateObservabilityCapabilityRun(run); err != nil {
		return ObservabilitySyntheticFixture{}, err
	}
	if !capabilityImageDigestPattern.MatchString(config.PushgatewayImage) || !capabilityImageDigestPattern.MatchString(config.LogEmitterImage) {
		return ObservabilitySyntheticFixture{}, errors.New("observability synthetic image is not immutable")
	}
	suffix := strings.TrimPrefix(run.RunID, "ok147-")
	fixture := ObservabilitySyntheticFixture{
		Format: ObservabilitySyntheticFixtureFormat, RunID: run.RunID, Namespace: run.Namespace,
		MetricsWorkload: "ok147-metrics-" + suffix, LogEmitter: "ok147-log-" + suffix,
		MetricName:         "ok_observability_contract_metric_" + suffix,
		AlertTriggerMetric: "ok_observability_synthetic_alert_trigger",
		LogMarker:          "OK147_OBSERVABILITY_LOG_" + suffix,
	}
	metadata := func(name string) map[string]any {
		return map[string]any{
			"name": name, "namespace": run.Namespace,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "ok147-runner", "openkubes.io/run-id": run.RunID,
			},
			"annotations": map[string]any{
				"openkubes.io/intent-revision": run.IntentRevision, "openkubes.io/platform-revision": run.PlatformRevision,
				"openkubes.io/execution-fixture": run.ExecutionFixture, "openkubes.io/capability-contract": run.ContractDigest,
				"openkubes.io/capability-executable": run.ExecutableDigest,
			},
		}
	}
	podSecurityContext := map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}}
	containerSecurityContext := map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}, "readOnlyRootFilesystem": true}
	selectorLabels := map[string]any{"app": fixture.MetricsWorkload, "openkubes.io/run-id": run.RunID}

	deploymentMetadata := metadata(fixture.MetricsWorkload)
	deploymentMetadata["labels"].(map[string]any)["app"] = fixture.MetricsWorkload
	serviceMetadata := metadata(fixture.MetricsWorkload)
	serviceMetadata["labels"].(map[string]any)["app"] = fixture.MetricsWorkload
	monitorMetadata := metadata(fixture.MetricsWorkload)
	monitorMetadata["labels"].(map[string]any)["release"] = "ok-observability"
	objects := []map[string]any{
		{
			"apiVersion": "apps/v1", "kind": "Deployment", "metadata": deploymentMetadata,
			"spec": map[string]any{
				"replicas": 1, "selector": map[string]any{"matchLabels": selectorLabels},
				"template": map[string]any{
					"metadata": map[string]any{"labels": selectorLabels},
					"spec": map[string]any{
						"automountServiceAccountToken": false, "enableServiceLinks": false, "securityContext": podSecurityContext,
						"containers": []any{map[string]any{
							"name": "pushgateway", "image": config.PushgatewayImage, "imagePullPolicy": "IfNotPresent",
							"ports":           []any{map[string]any{"name": "http", "containerPort": 9091}},
							"securityContext": containerSecurityContext,
							"resources":       map[string]any{"requests": map[string]any{"cpu": "10m", "memory": "32Mi"}, "limits": map[string]any{"cpu": "250m", "memory": "128Mi"}},
						}},
					},
				},
			},
		},
		{
			"apiVersion": "v1", "kind": "Service", "metadata": serviceMetadata,
			"spec": map[string]any{"selector": selectorLabels, "ports": []any{map[string]any{"name": "http", "port": 9091, "targetPort": 9091}}},
		},
		{
			"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor", "metadata": monitorMetadata,
			"spec": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": fixture.MetricsWorkload}}, "endpoints": []any{map[string]any{"port": "http", "interval": "10s"}}},
		},
		{
			"apiVersion": "v1", "kind": "Pod", "metadata": metadata(fixture.LogEmitter),
			"spec": map[string]any{
				"automountServiceAccountToken": false, "enableServiceLinks": false, "restartPolicy": "Never", "securityContext": podSecurityContext,
				"containers": []any{map[string]any{
					"name": "log-emitter", "image": config.LogEmitterImage, "imagePullPolicy": "IfNotPresent",
					"command": []any{"/bin/echo", fixture.LogMarker}, "securityContext": containerSecurityContext,
					"resources": map[string]any{"requests": map[string]any{"cpu": "1m", "memory": "4Mi"}, "limits": map[string]any{"cpu": "50m", "memory": "16Mi"}},
				}},
			},
		},
	}
	fixture.Objects = make([]CapabilityObject, 0, len(objects))
	for _, object := range objects {
		capabilityObject, err := encodeCapabilityObject(object)
		if err != nil {
			return ObservabilitySyntheticFixture{}, err
		}
		fixture.Objects = append(fixture.Objects, capabilityObject)
	}
	fixtureDigest, err := ObservabilitySyntheticFixtureDigest(fixture)
	if err != nil {
		return ObservabilitySyntheticFixture{}, err
	}
	fixture.FixtureDigest = fixtureDigest
	return fixture, nil
}

func ObservabilitySyntheticFixtureDigest(fixture ObservabilitySyntheticFixture) (string, error) {
	normalized := fixture
	normalized.FixtureDigest = ""
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return digest.SHA256(raw), nil
}

func encodeCapabilityObject(object map[string]any) (CapabilityObject, error) {
	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	metadata, _ := object["metadata"].(map[string]any)
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if apiVersion == "" || kind == "" || !capabilityNamespacePattern.MatchString(name) || !capabilityNamespacePattern.MatchString(namespace) || len(name) > 63 || len(namespace) > 63 {
		return CapabilityObject{}, errors.New("synthetic capability object identity is invalid")
	}
	resource, err := capabilityResource(apiVersion, kind)
	if err != nil {
		return CapabilityObject{}, err
	}
	prefix := "/api/v1"
	if apiVersion != "v1" {
		parts := strings.Split(apiVersion, "/")
		prefix = "/apis/" + parts[0] + "/" + parts[1]
	}
	collection := prefix + "/namespaces/" + namespace + "/" + resource
	raw, err := json.Marshal(object)
	if err != nil {
		return CapabilityObject{}, errors.New("encode synthetic capability object")
	}
	return CapabilityObject{
		Identity: CapabilityObjectIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name},
		Digest:   digest.SHA256(raw), CollectionPath: collection, ObjectPath: collection + "/" + name, Raw: raw,
	}, nil
}

func capabilityResource(apiVersion, kind string) (string, error) {
	switch apiVersion + "/" + kind {
	case "apps/v1/Deployment":
		return "deployments", nil
	case "v1/Service":
		return "services", nil
	case "monitoring.coreos.com/v1/ServiceMonitor":
		return "servicemonitors", nil
	case "v1/Pod":
		return "pods", nil
	default:
		return "", errors.New("synthetic capability object kind is not permitted")
	}
}

func validateObservabilityCapabilityRun(run ObservabilityCapabilityRun) error {
	if run.Format != ObservabilityCapabilityRunFormat || !capabilityNamespacePattern.MatchString(run.RunID) || len(run.RunID) != 30 || !strings.HasPrefix(run.RunID, "ok147-") || !capabilityNamespacePattern.MatchString(run.Namespace) || len(run.Namespace) > 63 || !runtimeInputUIDPattern.MatchString(run.TargetClusterUID) {
		return errors.New("observability capability run identity is invalid")
	}
	for _, value := range []string{run.IntentRevision, run.PlatformRevision, run.ExecutionFixture, run.ContractDigest, run.ExecutableDigest} {
		if !platformInputDigestPattern.MatchString(value) {
			return errors.New("observability capability run revision is invalid")
		}
	}
	return nil
}
