package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	capiClusterAPIVersion = "cluster.x-k8s.io/v1beta2"
	capiClusterKind       = "Cluster"
	intentRevisionKey     = "openkubes.io/intent-revision"
	maximumCAPIResponse   = 4 * 1024 * 1024
)

// CAPILifecycleObserverConfig binds the observer to exactly one CAPI Cluster.
// The client must already contain the trust roots for the management API.
type CAPILifecycleObserverConfig struct {
	Endpoint    string
	BearerToken string
	Namespace   string
	Name        string
	Client      *http.Client
}

// CAPILifecycleObserver performs one exact GET. It has no discovery, list,
// watch, mutation, retry, or status-publication path.
type CAPILifecycleObserver struct {
	endpoint  *url.URL
	token     string
	namespace string
	name      string
	client    *http.Client
}

// NewCAPILifecycleObserver constructs a bounded CAPI source observer.
func NewCAPILifecycleObserver(config CAPILifecycleObserverConfig) (*CAPILifecycleObserver, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("CAPI observer Kubernetes endpoint is invalid")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("CAPI observer Kubernetes endpoint must not contain a path")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("CAPI observer Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") {
		return nil, errors.New("CAPI observer bearer token is invalid")
	}
	if !validDNSLabel(config.Namespace) || !validDNSLabel(config.Name) {
		return nil, errors.New("CAPI observer Cluster identity is invalid")
	}
	if config.Client == nil {
		return nil, errors.New("CAPI observer requires an explicitly configured HTTP client")
	}
	client := *config.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path = ""
	return &CAPILifecycleObserver{
		endpoint: endpoint, token: config.BearerToken, namespace: config.Namespace,
		name: config.Name, client: &client,
	}, nil
}

// Collect returns normalized authoritative evidence for the two CAPI-owned
// lifecycle facts. Revision mismatch and stale generation remain explicit
// inputs for the aggregate evaluator and cannot become Ready=True.
func (observer *CAPILifecycleObserver) Collect(ctx context.Context, policy Policy) ([]Evidence, error) {
	if err := validatePolicy(policy, true); err != nil {
		return nil, err
	}
	cluster, err := observer.readCluster(ctx)
	if err != nil {
		return nil, err
	}
	return normalizeCAPICluster(cluster, policy)
}

// CollectBound establishes the raw-UID-free runtime correlation required
// after executor restart. The policy must not already carry a caller-selected
// UID; the exact Cluster GET supplies it and its digest must equal the durable
// lifecycle-submission binding before any Conditions are normalized.
func (observer *CAPILifecycleObserver) CollectBound(ctx context.Context, policy Policy, expectedTargetUIDDigest string) (Policy, []Evidence, error) {
	if err := validatePolicy(policy, false); err != nil || policy.TargetClusterUID != "" || !validDigest(expectedTargetUIDDigest) {
		return Policy{}, nil, errors.New("unbound CAPI observation policy or target identity digest is invalid")
	}
	cluster, err := observer.readCluster(ctx)
	if err != nil {
		return Policy{}, nil, err
	}
	if digest.SHA256([]byte(cluster.Metadata.UID)) != expectedTargetUIDDigest {
		return Policy{}, nil, errors.New("CAPI Cluster runtime identity differs from durable lifecycle binding")
	}
	bound, err := BindTarget(policy, cluster.Metadata.UID)
	if err != nil {
		return Policy{}, nil, err
	}
	evidence, err := normalizeCAPICluster(cluster, bound)
	if err != nil {
		return Policy{}, nil, err
	}
	return bound, evidence, nil
}

func (observer *CAPILifecycleObserver) readCluster(ctx context.Context) (capiCluster, error) {
	endpoint := *observer.endpoint
	endpoint.Path = "/apis/cluster.x-k8s.io/v1beta2/namespaces/" + observer.namespace + "/clusters/" + observer.name
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return capiCluster{}, errors.New("construct bounded CAPI observation request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+observer.token)
	response, err := observer.client.Do(request)
	if err != nil {
		return capiCluster{}, errors.New("bounded CAPI observation request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumCAPIResponse+1))
	if err != nil || len(raw) > maximumCAPIResponse {
		return capiCluster{}, errors.New("bounded CAPI observation response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return capiCluster{}, fmt.Errorf("bounded CAPI observation returned HTTP %d", response.StatusCode)
	}
	cluster, err := decodeCAPICluster(raw)
	if err != nil {
		return capiCluster{}, err
	}
	if cluster.APIVersion != capiClusterAPIVersion || cluster.Kind != capiClusterKind || cluster.Metadata.Namespace != observer.namespace || cluster.Metadata.Name != observer.name {
		return capiCluster{}, errors.New("CAPI observation object identity differs from the exact target")
	}
	if !validUID(cluster.Metadata.UID) || cluster.Metadata.ResourceVersion == "" || cluster.Metadata.Generation <= 0 {
		return capiCluster{}, errors.New("CAPI observation object lacks runtime identity")
	}
	return cluster, nil
}

func normalizeCAPICluster(cluster capiCluster, policy Policy) ([]Evidence, error) {
	observedRevision := cluster.Metadata.Annotations[intentRevisionKey]
	if !validDigest(observedRevision) {
		observedRevision = ""
	}

	conditions := make(map[string]capiCondition, 2)
	for _, item := range cluster.Status.Conditions {
		if item.Type != "InfrastructureReady" && item.Type != "ControlPlaneAvailable" {
			continue
		}
		if _, duplicate := conditions[item.Type]; duplicate {
			return nil, fmt.Errorf("CAPI Cluster contains duplicate %s Conditions", item.Type)
		}
		conditions[item.Type] = item
	}

	evidence := make([]Evidence, 0, 2)
	for _, conditionType := range []string{"InfrastructureReady", "ControlPlaneAvailable"} {
		item, present := conditions[conditionType]
		if !present {
			continue
		}
		if item.Status != "True" && item.Status != "False" && item.Status != "Unknown" {
			return nil, fmt.Errorf("CAPI %s status is invalid", conditionType)
		}
		reason := item.Reason
		if !validReason(reason) {
			reason = "SourceReasonUnavailable"
		}
		snapshot := capiEvidenceSnapshot{
			APIVersion: cluster.APIVersion, Kind: cluster.Kind, Namespace: cluster.Metadata.Namespace,
			Name: cluster.Metadata.Name, UID: cluster.Metadata.UID,
			ResourceVersion: cluster.Metadata.ResourceVersion, Generation: cluster.Metadata.Generation,
			IntentRevision: observedRevision, Type: conditionType, Status: item.Status,
			Reason: reason, ObservedGeneration: item.ObservedGeneration,
		}
		evidenceDigest, err := canonicalDigest(snapshot)
		if err != nil {
			return nil, fmt.Errorf("digest CAPI %s evidence: %w", conditionType, err)
		}
		itemEvidence := Evidence{
			Type: conditionType, Source: "CAPICluster", SourceUID: cluster.Metadata.UID,
			TargetClusterUID: policy.TargetClusterUID, Status: item.Status, Reason: reason,
			DesiredRevision: policy.IntentRevision, ObservedRevision: observedRevision,
			Generation: cluster.Metadata.Generation, ObservedGeneration: item.ObservedGeneration,
			EvidenceDigest: evidenceDigest,
		}
		if err := validateEvidenceShape(itemEvidence); err != nil {
			return nil, fmt.Errorf("normalize CAPI %s evidence: %w", conditionType, err)
		}
		evidence = append(evidence, itemEvidence)
	}
	return evidence, nil
}

type capiCluster struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Generation      int64             `json:"generation"`
		Annotations     map[string]string `json:"annotations"`
	} `json:"metadata"`
	Status struct {
		Conditions []capiCondition `json:"conditions"`
	} `json:"status"`
}

type capiCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ObservedGeneration int64  `json:"observedGeneration"`
}

type capiEvidenceSnapshot struct {
	APIVersion         string `json:"apiVersion"`
	Kind               string `json:"kind"`
	Namespace          string `json:"namespace"`
	Name               string `json:"name"`
	UID                string `json:"uid"`
	ResourceVersion    string `json:"resourceVersion"`
	Generation         int64  `json:"generation"`
	IntentRevision     string `json:"intentRevision,omitempty"`
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ObservedGeneration int64  `json:"observedGeneration"`
}

func decodeCAPICluster(raw []byte) (capiCluster, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value capiCluster
	if err := decoder.Decode(&value); err != nil {
		return capiCluster{}, errors.New("Kubernetes API returned invalid CAPI Cluster JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return capiCluster{}, errors.New("Kubernetes API returned trailing CAPI Cluster JSON")
	}
	return value, nil
}

func validDNSLabel(value string) bool {
	return len(value) > 0 && len(value) <= 63 && regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`).MatchString(value)
}

func validReason(value string) bool {
	return regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`).MatchString(value)
}
