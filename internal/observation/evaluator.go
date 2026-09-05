// Package observation implements the bounded aggregate evaluator proven by
// OK-141. It normalizes already authoritative source evidence; it does not
// query Kubernetes, publish status, or repair any source resource.
package observation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	PolicyFormat = "ok147-required-condition-policy/v1"
	BundleFormat = "ok147-observation-bundle/v1"
	ResultFormat = "ok147-aggregate-observation/v1"
)

var supportedConditions = map[string]struct{}{
	"InfrastructureReady":   {},
	"ControlPlaneAvailable": {},
	"NetworkReady":          {},
	"PlatformReady":         {},
}

// Policy is derived from the normalized Contract and therefore bound by R.
type Policy struct {
	Format                 string   `json:"format"`
	IntentRevision         string   `json:"intentRevision"`
	EnablementRevision     string   `json:"enablementRevision"`
	PlatformRevision       string   `json:"platformRevision"`
	TargetClusterUID       string   `json:"targetClusterUid"`
	Required               []string `json:"required"`
	NetworkObservationMode string   `json:"networkObservationMode,omitempty"`
}

// Evidence is one normalized statement from an authoritative source-specific
// observer. CAPI sources use generation correlation; bounded Network and
// Platform evaluators use exact revision correlation without inventing an
// observedGeneration field.
type Evidence struct {
	Type               string `json:"type"`
	Source             string `json:"source"`
	SourceUID          string `json:"sourceUid"`
	TargetClusterUID   string `json:"targetClusterUid"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	DesiredRevision    string `json:"desiredRevision"`
	ObservedRevision   string `json:"observedRevision"`
	Generation         int64  `json:"generation,omitempty"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	EvidenceDigest     string `json:"evidenceDigest"`
}

// BindTarget returns a runtime policy correlated to the immutable CAPI Cluster
// UID observed in the exact submission response.
func BindTarget(policy Policy, clusterUID string) (Policy, error) {
	if err := validatePolicy(policy, false); err != nil {
		return Policy{}, err
	}
	if !validUID(clusterUID) {
		return Policy{}, errors.New("target Cluster UID is invalid")
	}
	policy.TargetClusterUID = clusterUID
	return policy, nil
}

// Bundle is one bounded observation input. Missing required entries remain a
// valid input and evaluate to Unknown rather than being silently accepted.
type Bundle struct {
	Format         string     `json:"format"`
	IntentRevision string     `json:"intentRevision"`
	EvaluatedAt    string     `json:"evaluatedAt"`
	Evidence       []Evidence `json:"evidence"`
}

// Condition is the fail-closed normalized result for one required fact.
type Condition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Source string `json:"source,omitempty"`
}

// Receipt is deterministic aggregate evidence. It is not a durable status
// publication and cannot repair any source resource.
type Receipt struct {
	Format         string      `json:"format"`
	IntentRevision string      `json:"intentRevision"`
	PolicyDigest   string      `json:"policyDigest"`
	InputDigest    string      `json:"inputDigest"`
	Ready          string      `json:"ready"`
	Reason         string      `json:"reason"`
	Conditions     []Condition `json:"conditions"`
	EvaluatedAt    string      `json:"evaluatedAt"`
}

// VerifiedResult cannot be manufactured outside this package.
type VerifiedResult struct {
	receipt  Receipt
	digest   string
	verified bool
}

func (result VerifiedResult) Receipt() (Receipt, error) {
	if !result.verified {
		return Receipt{}, errors.New("observation result was not produced by evaluation")
	}
	return result.receipt, nil
}

func (result VerifiedResult) EvidenceDigest() (string, error) {
	if !result.verified {
		return "", errors.New("observation result was not produced by evaluation")
	}
	return result.digest, nil
}

// PolicyDigest returns the exact runtime policy identity, including the bound
// target Cluster UID.
func PolicyDigest(policy Policy) (string, error) {
	if err := validatePolicy(policy, true); err != nil {
		return "", err
	}
	return canonicalDigest(policy)
}

// PolicyFromContract extracts only immutable condition inputs from an already
// normalized Contract result.
func PolicyFromContract(result contract.Result) (Policy, error) {
	if !validDigest(result.NormalizedDigest) {
		return Policy{}, errors.New("normalized Contract revision is invalid")
	}
	root, ok := result.Normalized.(map[string]any)
	if !ok {
		return Policy{}, errors.New("normalized Contract is not an object")
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return Policy{}, errors.New("normalized Contract spec is not an object")
	}
	enablement, _ := spec["enablement"].(map[string]any)
	platform, _ := spec["platform"].(map[string]any)
	conditionSpec, _ := spec["conditions"].(map[string]any)
	eRevision, _ := enablement["revision"].(string)
	pRevision, _ := platform["revision"].(string)
	rawRequired, _ := conditionSpec["required"].([]any)
	if !validDigest(eRevision) || !validDigest(pRevision) || len(rawRequired) == 0 {
		return Policy{}, errors.New("normalized Contract lacks condition revision inputs")
	}
	required := make([]string, 0, len(rawRequired))
	seen := map[string]struct{}{}
	for _, raw := range rawRequired {
		name, ok := raw.(string)
		if !ok {
			return Policy{}, errors.New("required condition name is invalid")
		}
		if _, ok := supportedConditions[name]; !ok {
			return Policy{}, fmt.Errorf("required condition %q is unsupported", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return Policy{}, fmt.Errorf("required condition %q is duplicated", name)
		}
		seen[name] = struct{}{}
		required = append(required, name)
	}
	return Policy{
		Format: PolicyFormat, IntentRevision: result.NormalizedDigest,
		EnablementRevision: eRevision, PlatformRevision: pRevision, Required: required,
	}, nil
}

// Evaluate applies False-over-Unknown aggregation. Missing, stale, foreign or
// revision-mismatched evidence can never produce Ready=True.
func Evaluate(policy Policy, bundle Bundle) (VerifiedResult, error) {
	if err := validatePolicy(policy, true); err != nil {
		return VerifiedResult{}, err
	}
	if bundle.Format != BundleFormat || bundle.IntentRevision != policy.IntentRevision {
		return VerifiedResult{}, errors.New("observation bundle format or intent revision differs from policy")
	}
	if _, err := time.Parse(time.RFC3339Nano, bundle.EvaluatedAt); err != nil {
		return VerifiedResult{}, errors.New("observation evaluation time is invalid")
	}
	if len(bundle.Evidence) > len(policy.Required)+4 {
		return VerifiedResult{}, errors.New("observation bundle contains too many source statements")
	}
	required := make(map[string]struct{}, len(policy.Required))
	for _, name := range policy.Required {
		required[name] = struct{}{}
	}
	byType := make(map[string][]Evidence, len(bundle.Evidence))
	for _, item := range bundle.Evidence {
		if _, ok := supportedConditions[item.Type]; !ok {
			return VerifiedResult{}, fmt.Errorf("observation condition %q is unsupported", item.Type)
		}
		if _, ok := required[item.Type]; !ok {
			return VerifiedResult{}, fmt.Errorf("observation condition %q is not in the required profile", item.Type)
		}
		if err := validateEvidenceShape(item); err != nil {
			return VerifiedResult{}, fmt.Errorf("observation condition %s: %w", item.Type, err)
		}
		byType[item.Type] = append(byType[item.Type], item)
	}

	conditions := make([]Condition, 0, len(policy.Required))
	hasFalse := false
	hasUnknown := false
	for _, name := range policy.Required {
		items := byType[name]
		var result Condition
		switch len(items) {
		case 0:
			result = Condition{Type: name, Status: "Unknown", Reason: "RequiredEvidenceMissing"}
		case 1:
			result = evaluateEvidence(policy, items[0])
		default:
			result = Condition{Type: name, Status: "Unknown", Reason: "ConflictingAuthority"}
		}
		conditions = append(conditions, result)
		hasFalse = hasFalse || result.Status == "False"
		hasUnknown = hasUnknown || result.Status == "Unknown"
	}

	ready, reason := "True", "AllRequiredConditionsSatisfied"
	if hasFalse {
		ready, reason = "False", "RequiredConditionFailed"
	} else if hasUnknown {
		ready, reason = "Unknown", aggregateUnknownReason(conditions)
	}
	policyDigest, err := PolicyDigest(policy)
	if err != nil {
		return VerifiedResult{}, err
	}
	inputDigest, err := canonicalDigest(bundle)
	if err != nil {
		return VerifiedResult{}, err
	}
	receipt := Receipt{
		Format: ResultFormat, IntentRevision: policy.IntentRevision, PolicyDigest: policyDigest,
		InputDigest: inputDigest, Ready: ready, Reason: reason, Conditions: conditions,
		EvaluatedAt: bundle.EvaluatedAt,
	}
	receiptDigest, err := canonicalDigest(receipt)
	if err != nil {
		return VerifiedResult{}, err
	}
	return VerifiedResult{receipt: receipt, digest: receiptDigest, verified: true}, nil
}

func validatePolicy(policy Policy, requireTarget bool) error {
	if policy.Format != PolicyFormat || !validDigest(policy.IntentRevision) || !validDigest(policy.EnablementRevision) || !validDigest(policy.PlatformRevision) || len(policy.Required) == 0 {
		return errors.New("observation policy is invalid")
	}
	if requireTarget && !validUID(policy.TargetClusterUID) {
		return errors.New("observation policy has no valid target Cluster UID")
	}
	if policy.NetworkObservationMode != "" && policy.NetworkObservationMode != "deferred-mvp/v1" {
		return errors.New("observation policy network mode is unsupported")
	}
	if policy.NetworkObservationMode != "" && (len(policy.Required) != 1 || policy.Required[0] != "NetworkReady") {
		return errors.New("observation policy network mode requires only NetworkReady")
	}
	seen := map[string]struct{}{}
	for _, name := range policy.Required {
		if _, ok := supportedConditions[name]; !ok {
			return fmt.Errorf("observation policy condition %q is unsupported", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("observation policy condition %q is duplicated", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func validateEvidenceShape(value Evidence) error {
	if !validUID(value.SourceUID) || !validUID(value.TargetClusterUID) || !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`).MatchString(value.Reason) || !validDigest(value.DesiredRevision) || (value.ObservedRevision != "" && !validDigest(value.ObservedRevision)) || !validDigest(value.EvidenceDigest) {
		return errors.New("identity, revision, reason, or evidence digest is invalid")
	}
	if value.Status != "True" && value.Status != "False" && value.Status != "Unknown" {
		return errors.New("status is invalid")
	}
	expectedSource := sourceFor(value.Type)
	if value.Source != expectedSource {
		return fmt.Errorf("source %q differs from required %q", value.Source, expectedSource)
	}
	if isCAPISource(value.Type) {
		if value.Generation <= 0 || value.ObservedGeneration < 0 {
			return errors.New("CAPI generation fields are invalid")
		}
	} else if value.Generation != 0 || value.ObservedGeneration != 0 {
		return errors.New("non-CAPI evidence must not invent generation fields")
	}
	return nil
}

func evaluateEvidence(policy Policy, value Evidence) Condition {
	condition := Condition{Type: value.Type, Source: value.Source}
	if value.TargetClusterUID != policy.TargetClusterUID || isCAPISource(value.Type) && value.SourceUID != policy.TargetClusterUID {
		condition.Status, condition.Reason = "Unknown", "RevisionCorrelationUnproven"
		return condition
	}
	expectedRevision := policy.IntentRevision
	if value.Type == "NetworkReady" {
		expectedRevision = policy.EnablementRevision
	} else if value.Type == "PlatformReady" {
		expectedRevision = policy.PlatformRevision
	}
	if value.DesiredRevision != expectedRevision || value.ObservedRevision != expectedRevision {
		condition.Status, condition.Reason = "Unknown", "RevisionCorrelationUnproven"
		return condition
	}
	if isCAPISource(value.Type) && value.ObservedGeneration != value.Generation {
		condition.Status, condition.Reason = "Unknown", "SourceObservationStale"
		return condition
	}
	condition.Status = value.Status
	condition.Reason = value.Reason
	return condition
}

func aggregateUnknownReason(conditions []Condition) string {
	for _, preferred := range []string{"ConflictingAuthority", "RevisionCorrelationUnproven", "SourceObservationStale", "RequiredEvidenceMissing"} {
		for _, condition := range conditions {
			if condition.Status == "Unknown" && condition.Reason == preferred {
				return preferred
			}
		}
	}
	return "ObserverUnavailable"
}

func sourceFor(condition string) string {
	switch condition {
	case "InfrastructureReady", "ControlPlaneAvailable":
		return "CAPICluster"
	case "NetworkReady":
		return "BoundedNetworkEvaluator"
	case "PlatformReady":
		return "BoundedPlatformEvaluator"
	default:
		return ""
	}
}

func isCAPISource(condition string) bool {
	return condition == "InfrastructureReady" || condition == "ControlPlaneAvailable"
}

func validDigest(value string) bool {
	return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value)
}

func validUID(value string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(value)
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(generic)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}
