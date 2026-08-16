package observation

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	NetworkProfileFormat  = "ok147-network-profile/v1"
	NetworkSnapshotFormat = "ok147-network-snapshot/v1"
)

// NetworkProfile contains the reviewed, immutable semantics behind E. The
// runner adapter loads it from a separately digest-bound strict-JSON document;
// this evaluator deliberately has no API client or command-execution path.
type NetworkProfile struct {
	Format                       string        `json:"format"`
	IntentRevision               string        `json:"intentRevision"`
	EnablementRevision           string        `json:"enablementRevision"`
	ExpectedNodeCount            int           `json:"expectedNodeCount"`
	ExpectedHCPSpecDigest        string        `json:"expectedHcpSpecDigest"`
	ExpectedHRPSpecDigest        string        `json:"expectedHrpSpecDigest"`
	ExpectedImages               NetworkImages `json:"expectedImages"`
	MinimumProbeFreshnessSeconds int64         `json:"minimumProbeFreshnessSeconds"`
	MaximumProbeIntervalSeconds  int64         `json:"maximumProbeIntervalSeconds"`
	CacheExposureSeconds         int64         `json:"cacheExposureSeconds"`
}

type NetworkImages struct {
	CiliumAgent    string `json:"ciliumAgent"`
	CiliumEnvoy    string `json:"ciliumEnvoy"`
	CiliumOperator string `json:"ciliumOperator"`
}

// NetworkSnapshot is a redaction-safe normalized input. It contains no Secret,
// kubeconfig, token, certificate, endpoint, IP address, raw API object, log, or
// raw probe output.
type NetworkSnapshot struct {
	Format             string             `json:"format"`
	ObservedAt         string             `json:"observedAt"`
	TargetClusterUID   string             `json:"targetClusterUid"`
	IntentRevision     string             `json:"intentRevision"`
	EnablementRevision string             `json:"enablementRevision"`
	HCP                NetworkAddonSource `json:"hcp"`
	HRPCount           int                `json:"hrpCount"`
	HRP                NetworkAddonSource `json:"hrp"`
	Nodes              []NetworkNode      `json:"nodes"`
	Components         []NetworkComponent `json:"components"`
	AgentPods          []NetworkAgentPod  `json:"agentPods"`
	Probe              NetworkProbe       `json:"probe"`
}

type NetworkAddonSource struct {
	UID                      string                   `json:"uid"`
	Generation               int64                    `json:"generation"`
	StatusObservedGeneration int64                    `json:"statusObservedGeneration"`
	SpecDigest               string                   `json:"specDigest"`
	IntentRevision           string                   `json:"intentRevision"`
	EnablementRevision       string                   `json:"enablementRevision"`
	OwnerUID                 string                   `json:"ownerUid,omitempty"`
	TargetClusterUID         string                   `json:"targetClusterUid"`
	TargetSelected           bool                     `json:"targetSelected"`
	ReleaseStatus            string                   `json:"releaseStatus,omitempty"`
	ReleaseRevision          int64                    `json:"releaseRevision,omitempty"`
	Conditions               []NetworkSourceCondition `json:"conditions"`
}

type NetworkSourceCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ObservedGeneration int64  `json:"observedGeneration"`
}

type NetworkNode struct {
	UID                      string `json:"uid"`
	ProviderID               string `json:"providerId"`
	Ready                    string `json:"ready"`
	NetworkUnavailable       string `json:"networkUnavailable"`
	NetworkUnavailableReason string `json:"networkUnavailableReason"`
}

type NetworkComponent struct {
	ID                 string `json:"id"`
	UID                string `json:"uid"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observedGeneration"`
	Desired            int64  `json:"desired"`
	Updated            int64  `json:"updated"`
	Available          int64  `json:"available"`
	Ready              int64  `json:"ready"`
	Image              string `json:"image"`
}

type NetworkAgentPod struct {
	UID     string `json:"uid"`
	NodeUID string `json:"nodeUid"`
	Phase   string `json:"phase"`
	Ready   bool   `json:"ready"`
}

type NetworkProbe struct {
	ResponseTimestamp         string             `json:"responseTimestamp"`
	ProbeIntervalMilliseconds int64              `json:"probeIntervalMilliseconds"`
	Paths                     []NetworkProbePath `json:"paths"`
}

type NetworkProbePath struct {
	NodeUID       string `json:"nodeUid"`
	Scope         string `json:"scope"`
	Protocol      string `json:"protocol"`
	StatusPresent bool   `json:"statusPresent"`
	Status        string `json:"status,omitempty"`
	LastProbed    string `json:"lastProbed"`
}

// EvaluateNetworkSnapshot translates the proven OK-141 network semantics into
// one normalized source statement. Convergence gaps are Unknown; current
// invariant violations are False. Neither can become aggregate Ready=True.
func EvaluateNetworkSnapshot(policy Policy, profile NetworkProfile, snapshot NetworkSnapshot) (Evidence, error) {
	if err := validatePolicy(policy, true); err != nil {
		return Evidence{}, err
	}
	if err := validateNetworkProfile(policy, profile); err != nil {
		return Evidence{}, err
	}
	if err := validateNetworkSnapshotShape(snapshot); err != nil {
		return Evidence{}, err
	}
	snapshotDigest, err := canonicalDigest(snapshot)
	if err != nil {
		return Evidence{}, err
	}
	profileDigest, err := NetworkProfileDigest(profile)
	if err != nil {
		return Evidence{}, err
	}
	evidenceDigest, err := canonicalDigest(struct {
		Format         string `json:"format"`
		ProfileDigest  string `json:"profileDigest"`
		SnapshotDigest string `json:"snapshotDigest"`
	}{Format: "ok147-network-evidence-binding/v1", ProfileDigest: profileDigest, SnapshotDigest: snapshotDigest})
	if err != nil {
		return Evidence{}, err
	}
	observedRevision := snapshot.EnablementRevision
	if !validDigest(observedRevision) {
		observedRevision = ""
	}
	status, reason := evaluateNetworkState(policy, profile, snapshot)
	evidence := Evidence{
		Type: "NetworkReady", Source: "BoundedNetworkEvaluator",
		SourceUID:        "network-evidence-" + evidenceDigest[len("sha256:"):len("sha256:")+32],
		TargetClusterUID: policy.TargetClusterUID, Status: status, Reason: reason,
		DesiredRevision: policy.EnablementRevision, ObservedRevision: observedRevision,
		EvidenceDigest: evidenceDigest,
	}
	if err := validateEvidenceShape(evidence); err != nil {
		return Evidence{}, fmt.Errorf("normalize NetworkReady evidence: %w", err)
	}
	return evidence, nil
}

func validateNetworkProfile(policy Policy, profile NetworkProfile) error {
	if profile.Format != NetworkProfileFormat || profile.IntentRevision != policy.IntentRevision || profile.EnablementRevision != policy.EnablementRevision {
		return errors.New("network profile identity differs from observation policy")
	}
	return ValidateNetworkProfile(profile)
}

// ValidateNetworkProfile checks the complete intrinsic profile shape without
// inferring its R or E identity from a runtime source.
func ValidateNetworkProfile(profile NetworkProfile) error {
	if profile.Format != NetworkProfileFormat || !validDigest(profile.IntentRevision) || !validDigest(profile.EnablementRevision) {
		return errors.New("network profile format or revision identity is invalid")
	}
	if profile.ExpectedNodeCount < 1 || profile.ExpectedNodeCount > 100 || !validDigest(profile.ExpectedHCPSpecDigest) || !validDigest(profile.ExpectedHRPSpecDigest) {
		return errors.New("network profile object expectations are invalid")
	}
	for _, image := range []string{profile.ExpectedImages.CiliumAgent, profile.ExpectedImages.CiliumEnvoy, profile.ExpectedImages.CiliumOperator} {
		if !validPinnedImage(image) {
			return errors.New("network profile contains a mutable or invalid image")
		}
	}
	if profile.MinimumProbeFreshnessSeconds < 30 || profile.MinimumProbeFreshnessSeconds > 600 || profile.MaximumProbeIntervalSeconds < 30 || profile.MaximumProbeIntervalSeconds > 600 || profile.CacheExposureSeconds < 0 || profile.CacheExposureSeconds > 300 {
		return errors.New("network profile probe freshness boundary is invalid")
	}
	return nil
}

// NetworkProfileDigest identifies the canonical semantic profile consumed by
// NetworkReady evaluation. Whitespace and JSON object ordering are irrelevant.
func NetworkProfileDigest(profile NetworkProfile) (string, error) {
	if err := ValidateNetworkProfile(profile); err != nil {
		return "", err
	}
	return canonicalDigest(profile)
}

func validateNetworkSnapshotShape(snapshot NetworkSnapshot) error {
	if snapshot.Format != NetworkSnapshotFormat || !validUID(snapshot.TargetClusterUID) || snapshot.ObservedAt == "" {
		return errors.New("network snapshot identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.ObservedAt); err != nil {
		return errors.New("network snapshot observation time is invalid")
	}
	if (snapshot.IntentRevision != "" && !validDigest(snapshot.IntentRevision)) || (snapshot.EnablementRevision != "" && !validDigest(snapshot.EnablementRevision)) {
		return errors.New("network snapshot revision is malformed")
	}
	if snapshot.HRPCount < 0 || snapshot.HRPCount > 10 || len(snapshot.Nodes) > 100 || len(snapshot.Components) > 10 || len(snapshot.AgentPods) > 100 || len(snapshot.Probe.Paths) > 400 {
		return errors.New("network snapshot exceeds bounded collection limits")
	}
	if len(snapshot.HCP.Conditions) > 16 || len(snapshot.HRP.Conditions) > 16 {
		return errors.New("network snapshot exceeds bounded Condition limits")
	}
	for _, node := range snapshot.Nodes {
		if len(node.ProviderID) > 512 {
			return errors.New("network snapshot contains an oversized provider identity")
		}
	}
	for _, component := range snapshot.Components {
		if len(component.ID) > 64 || len(component.Image) > 1024 {
			return errors.New("network snapshot contains oversized component identity")
		}
	}
	return nil
}

func evaluateNetworkState(policy Policy, profile NetworkProfile, snapshot NetworkSnapshot) (string, string) {
	if snapshot.TargetClusterUID != policy.TargetClusterUID || snapshot.IntentRevision != policy.IntentRevision || snapshot.EnablementRevision != policy.EnablementRevision {
		return "Unknown", "RevisionCorrelationUnproven"
	}
	if status, reason := evaluateAddonSource(snapshot.HCP, snapshot.TargetClusterUID, "", profile.ExpectedHCPSpecDigest, policy, []string{"Ready", "HelmReleaseProxySpecsUpToDate", "HelmReleaseProxiesReady"}, "EnablementOwner"); status != "True" {
		return status, reason
	}
	if snapshot.HRPCount != 1 {
		return "Unknown", "EnablementReleaseNotReady"
	}
	if status, reason := evaluateAddonSource(snapshot.HRP, snapshot.TargetClusterUID, snapshot.HCP.UID, profile.ExpectedHRPSpecDigest, policy, []string{"Ready", "HelmReleaseReady"}, "EnablementRelease"); status != "True" {
		return status, reason
	}
	if snapshot.HRP.ReleaseStatus != "deployed" || snapshot.HRP.ReleaseRevision < 1 {
		return "Unknown", "EnablementReleaseNotReady"
	}
	if len(snapshot.Nodes) != profile.ExpectedNodeCount {
		return "Unknown", "NodeInventoryNotReady"
	}
	nodeUIDs := make(map[string]struct{}, len(snapshot.Nodes))
	providerIDs := make(map[string]struct{}, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if !validUID(node.UID) || node.ProviderID == "" {
			return "False", "NodeIdentityInvalid"
		}
		if _, duplicate := nodeUIDs[node.UID]; duplicate {
			return "False", "NodeIdentityInvalid"
		}
		if _, duplicate := providerIDs[node.ProviderID]; duplicate {
			return "False", "NodeIdentityInvalid"
		}
		nodeUIDs[node.UID], providerIDs[node.ProviderID] = struct{}{}, struct{}{}
		if node.Ready != "True" || node.NetworkUnavailable != "False" || node.NetworkUnavailableReason != "CiliumIsUp" {
			return "Unknown", "NodeNetworkNotReady"
		}
	}
	if status, reason := evaluateNetworkComponents(profile, snapshot.Components); status != "True" {
		return status, reason
	}
	if len(snapshot.AgentPods) != profile.ExpectedNodeCount {
		return "Unknown", "CiliumAgentPodsNotReady"
	}
	podNodes := make(map[string]struct{}, len(snapshot.AgentPods))
	for _, pod := range snapshot.AgentPods {
		if !validUID(pod.UID) || pod.Phase != "Running" || !pod.Ready {
			return "Unknown", "CiliumAgentPodsNotReady"
		}
		if _, exists := nodeUIDs[pod.NodeUID]; !exists {
			return "False", "CiliumNodeCoverageInvalid"
		}
		if _, duplicate := podNodes[pod.NodeUID]; duplicate {
			return "False", "CiliumNodeCoverageInvalid"
		}
		podNodes[pod.NodeUID] = struct{}{}
	}
	if len(podNodes) != len(nodeUIDs) {
		return "False", "CiliumNodeCoverageInvalid"
	}
	return evaluateNetworkProbe(profile, snapshot, nodeUIDs)
}

func evaluateAddonSource(source NetworkAddonSource, targetUID, ownerUID, specDigest string, policy Policy, required []string, reasonPrefix string) (string, string) {
	if !validUID(source.UID) || source.SpecDigest != specDigest || source.IntentRevision != policy.IntentRevision || source.EnablementRevision != policy.EnablementRevision || source.TargetClusterUID != targetUID || !source.TargetSelected || source.OwnerUID != ownerUID {
		return "False", reasonPrefix + "IdentityMismatch"
	}
	if source.Generation <= 0 || source.StatusObservedGeneration != source.Generation {
		return "Unknown", reasonPrefix + "NotReady"
	}
	conditions := make(map[string]NetworkSourceCondition, len(source.Conditions))
	for _, condition := range source.Conditions {
		if _, duplicate := conditions[condition.Type]; duplicate {
			return "False", reasonPrefix + "IdentityMismatch"
		}
		conditions[condition.Type] = condition
	}
	for _, name := range required {
		condition, exists := conditions[name]
		if !exists || condition.Status != "True" || condition.ObservedGeneration != source.Generation {
			return "Unknown", reasonPrefix + "NotReady"
		}
	}
	return "True", reasonPrefix + "Ready"
}

func evaluateNetworkComponents(profile NetworkProfile, components []NetworkComponent) (string, string) {
	expected := map[string]struct {
		desired int64
		image   string
	}{
		"cilium-agent":    {int64(profile.ExpectedNodeCount), profile.ExpectedImages.CiliumAgent},
		"cilium-envoy":    {int64(profile.ExpectedNodeCount), profile.ExpectedImages.CiliumEnvoy},
		"cilium-operator": {1, profile.ExpectedImages.CiliumOperator},
	}
	if len(components) != len(expected) {
		return "Unknown", "CiliumRolloutNotReady"
	}
	seen := map[string]struct{}{}
	for _, component := range components {
		want, exists := expected[component.ID]
		if !exists {
			return "False", "CiliumComponentIdentityInvalid"
		}
		if _, duplicate := seen[component.ID]; duplicate {
			return "False", "CiliumComponentIdentityInvalid"
		}
		seen[component.ID] = struct{}{}
		if !validUID(component.UID) || component.Generation <= 0 || component.ObservedGeneration != component.Generation || component.Desired != want.desired || component.Updated != want.desired || component.Available != want.desired || component.Ready != want.desired {
			return "Unknown", "CiliumRolloutNotReady"
		}
		if component.Image != want.image {
			return "False", "CiliumImageMismatch"
		}
	}
	return "True", "CiliumRolloutReady"
}

func evaluateNetworkProbe(profile NetworkProfile, snapshot NetworkSnapshot, nodeUIDs map[string]struct{}) (string, string) {
	observedAt, _ := time.Parse(time.RFC3339Nano, snapshot.ObservedAt)
	responseAt, err := time.Parse(time.RFC3339Nano, snapshot.Probe.ResponseTimestamp)
	if err != nil || snapshot.Probe.ProbeIntervalMilliseconds <= 0 || snapshot.Probe.ProbeIntervalMilliseconds > profile.MaximumProbeIntervalSeconds*1000 {
		return "False", "FunctionalProbeInvalid"
	}
	probeIntervalSeconds := float64(snapshot.Probe.ProbeIntervalMilliseconds) / 1000
	maximumAge := math.Max(float64(profile.MinimumProbeFreshnessSeconds), 2*probeIntervalSeconds+float64(profile.CacheExposureSeconds))
	if age := observedAt.Sub(responseAt).Seconds(); age < -5 || age > maximumAge {
		return "False", "FunctionalProbeStale"
	}
	expectedPathCount := len(nodeUIDs) * 4
	if len(snapshot.Probe.Paths) != expectedPathCount {
		return "False", "FunctionalProbeCoverageInvalid"
	}
	seen := make([]string, 0, len(snapshot.Probe.Paths))
	for _, path := range snapshot.Probe.Paths {
		if _, exists := nodeUIDs[path.NodeUID]; !exists || path.Scope != "host" && path.Scope != "health-endpoint" || path.Protocol != "http" && path.Protocol != "icmp" {
			return "False", "FunctionalProbeCoverageInvalid"
		}
		key := path.NodeUID + "/" + path.Scope + "/" + path.Protocol
		seen = append(seen, key)
		if !path.StatusPresent && path.Status != "" {
			return "False", "FunctionalProbeInvalid"
		}
		if path.StatusPresent && path.Status != "" {
			return "False", "FunctionalProbeFailed"
		}
		lastProbed, err := time.Parse(time.RFC3339Nano, path.LastProbed)
		if err != nil {
			return "False", "FunctionalProbeInvalid"
		}
		if age := observedAt.Sub(lastProbed).Seconds(); age < -5 || age > maximumAge {
			return "False", "FunctionalProbeStale"
		}
	}
	sort.Strings(seen)
	for index := 1; index < len(seen); index++ {
		if seen[index] == seen[index-1] {
			return "False", "FunctionalProbeCoverageInvalid"
		}
	}
	return "True", "NetworkReady"
}

func validPinnedImage(value string) bool {
	const separator = "@sha256:"
	index := len(value) - 64 - len(separator)
	if index <= 0 || value[index:index+len(separator)] != separator {
		return false
	}
	return validDigest("sha256:" + value[index+len(separator):])
}
