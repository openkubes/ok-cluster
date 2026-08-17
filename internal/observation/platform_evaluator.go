package observation

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	PlatformProfileFormat             = "ok147-platform-profile/v1"
	PlatformApplicationSnapshotFormat = "ok147-platform-application-snapshot/v1"
	PlatformSnapshotFormat            = "ok147-platform-snapshot/v1"
	PlatformCapabilityFormat          = "ok147-platform-capability/v1"
)

// PlatformProfile is the immutable, reviewed meaning of P consumed by the
// bounded evaluator. It identifies exact Argo Applications and a separate
// capability proof; Argo health alone is deliberately insufficient.
type PlatformProfile struct {
	Format                      string                           `json:"format"`
	IntentRevision              string                           `json:"intentRevision"`
	PlatformRevision            string                           `json:"platformRevision"`
	ExecutionFixture            string                           `json:"executionFixture"`
	TargetIdentityScheme        string                           `json:"targetIdentityScheme"`
	ArgoNamespace               string                           `json:"argoNamespace"`
	RegistrationName            string                           `json:"registrationName"`
	RequiredApplications        []PlatformApplicationExpectation `json:"requiredApplications"`
	CapabilityContractDigest    string                           `json:"capabilityContractDigest"`
	CapabilityExecutableDigest  string                           `json:"capabilityExecutableDigest"`
	MaximumCapabilityAgeSeconds int64                            `json:"maximumCapabilityAgeSeconds"`
}

type PlatformApplicationExpectation struct {
	Name       string `json:"name"`
	SpecDigest string `json:"specDigest"`
}

// PlatformSnapshot contains only normalized, redaction-safe observations. It
// contains no Secret, token, kubeconfig, endpoint, raw Application, message,
// log, or capability output.
type PlatformSnapshot struct {
	Format           string                     `json:"format"`
	ObservedAt       string                     `json:"observedAt"`
	TargetClusterUID string                     `json:"targetClusterUid"`
	Applications     []PlatformApplicationState `json:"applications"`
	Capability       PlatformCapabilityState    `json:"capability"`
}

type PlatformApplicationState struct {
	Name                  string `json:"name"`
	UID                   string `json:"uid"`
	ResourceVersion       string `json:"resourceVersion"`
	IntentRevision        string `json:"intentRevision"`
	PlatformRevision      string `json:"platformRevision"`
	ExecutionFixture      string `json:"executionFixture"`
	SpecDigest            string `json:"specDigest"`
	DesiredSourceRevision string `json:"desiredSourceRevision"`
	AppliedSourceRevision string `json:"appliedSourceRevision"`
	SyncStatus            string `json:"syncStatus"`
	HealthStatus          string `json:"healthStatus"`
}

// PlatformApplicationSnapshot is the capability-execution gate. It contains
// only exact, normalized Argo Application observations and deliberately no
// capability assertion.
type PlatformApplicationSnapshot struct {
	Format           string                     `json:"format"`
	ObservedAt       string                     `json:"observedAt"`
	TargetClusterUID string                     `json:"targetClusterUid"`
	Applications     []PlatformApplicationState `json:"applications"`
}

// PlatformCapabilityState is produced by a separately bounded capability
// mechanism. The Argo reader cannot manufacture or execute this assertion.
type PlatformCapabilityState struct {
	Format           string `json:"format"`
	ObservedAt       string `json:"observedAt"`
	TargetClusterUID string `json:"targetClusterUid"`
	IntentRevision   string `json:"intentRevision"`
	PlatformRevision string `json:"platformRevision"`
	ExecutionFixture string `json:"executionFixture"`
	ContractDigest   string `json:"contractDigest"`
	ExecutableDigest string `json:"executableDigest"`
	Passed           bool   `json:"passed"`
	EvidenceDigest   string `json:"evidenceDigest"`
}

// EvaluatePlatformSnapshot emits one PlatformReady statement. It observes and
// correlates only; it cannot sync Argo, repair a target or run capability code.
func EvaluatePlatformSnapshot(policy Policy, profile PlatformProfile, snapshot PlatformSnapshot) (Evidence, error) {
	if err := validatePolicy(policy, true); err != nil {
		return Evidence{}, err
	}
	if err := validatePlatformProfile(policy, profile); err != nil {
		return Evidence{}, err
	}
	if err := validatePlatformSnapshotShape(snapshot); err != nil {
		return Evidence{}, err
	}
	profileDigest, err := PlatformProfileDigest(profile)
	if err != nil {
		return Evidence{}, err
	}
	snapshotDigest, err := canonicalDigest(snapshot)
	if err != nil {
		return Evidence{}, err
	}
	evidenceDigest, err := canonicalDigest(struct {
		Format         string `json:"format"`
		ProfileDigest  string `json:"profileDigest"`
		SnapshotDigest string `json:"snapshotDigest"`
	}{Format: "ok147-platform-evidence-binding/v1", ProfileDigest: profileDigest, SnapshotDigest: snapshotDigest})
	if err != nil {
		return Evidence{}, err
	}
	status, reason, observedRevision := evaluatePlatformState(policy, profile, snapshot)
	evidence := Evidence{
		Type: "PlatformReady", Source: "BoundedPlatformEvaluator",
		SourceUID:        "platform-evidence-" + evidenceDigest[len("sha256:"):len("sha256:")+32],
		TargetClusterUID: policy.TargetClusterUID, Status: status, Reason: reason,
		DesiredRevision: policy.PlatformRevision, ObservedRevision: observedRevision,
		EvidenceDigest: evidenceDigest,
	}
	if err := validateEvidenceShape(evidence); err != nil {
		return Evidence{}, fmt.Errorf("normalize PlatformReady evidence: %w", err)
	}
	return evidence, nil
}

// EvaluatePlatformApplications determines whether capability execution may
// begin. A True result is only possible when every exact Application is bound
// to the current R/P/fixture and its desired revision is Synced and Healthy.
func EvaluatePlatformApplications(policy Policy, profile PlatformProfile, snapshot PlatformApplicationSnapshot) (Evidence, error) {
	if err := validatePolicy(policy, true); err != nil {
		return Evidence{}, err
	}
	if err := validatePlatformProfile(policy, profile); err != nil {
		return Evidence{}, err
	}
	if err := validatePlatformApplicationSnapshotShape(snapshot); err != nil {
		return Evidence{}, err
	}
	profileDigest, err := PlatformProfileDigest(profile)
	if err != nil {
		return Evidence{}, err
	}
	snapshotDigest, err := canonicalDigest(snapshot)
	if err != nil {
		return Evidence{}, err
	}
	evidenceDigest, err := canonicalDigest(struct {
		Format         string `json:"format"`
		ProfileDigest  string `json:"profileDigest"`
		SnapshotDigest string `json:"snapshotDigest"`
	}{Format: "ok147-platform-application-gate-binding/v1", ProfileDigest: profileDigest, SnapshotDigest: snapshotDigest})
	if err != nil {
		return Evidence{}, err
	}
	status, reason, observedRevision := evaluatePlatformApplications(policy, profile, snapshot.TargetClusterUID, snapshot.Applications)
	evidence := Evidence{
		Type: "PlatformReady", Source: "BoundedPlatformEvaluator",
		SourceUID:        "platform-gate-" + evidenceDigest[len("sha256:"):len("sha256:")+32],
		TargetClusterUID: policy.TargetClusterUID, Status: status, Reason: reason,
		DesiredRevision: policy.PlatformRevision, ObservedRevision: observedRevision,
		EvidenceDigest: evidenceDigest,
	}
	if err := validateEvidenceShape(evidence); err != nil {
		return Evidence{}, fmt.Errorf("normalize platform Application gate evidence: %w", err)
	}
	return evidence, nil
}

func ValidatePlatformProfile(profile PlatformProfile) error {
	if profile.Format != PlatformProfileFormat || !validDigest(profile.IntentRevision) || !validDigest(profile.PlatformRevision) || !validDigest(profile.ExecutionFixture) || profile.TargetIdentityScheme != "capi-cluster-uid/v1" {
		return errors.New("platform profile format or revision identity is invalid")
	}
	if !validDNSLabel(profile.ArgoNamespace) || !validDNSLabel(profile.RegistrationName) || len(profile.RequiredApplications) == 0 || len(profile.RequiredApplications) > 20 {
		return errors.New("platform profile target or Application set is invalid")
	}
	seen := map[string]struct{}{}
	for _, application := range profile.RequiredApplications {
		if !validDNSLabel(application.Name) || !validDigest(application.SpecDigest) {
			return errors.New("platform profile Application identity is invalid")
		}
		if _, duplicate := seen[application.Name]; duplicate {
			return errors.New("platform profile contains a duplicate Application")
		}
		seen[application.Name] = struct{}{}
	}
	if !validDigest(profile.CapabilityContractDigest) || !validDigest(profile.CapabilityExecutableDigest) || profile.MaximumCapabilityAgeSeconds < 60 || profile.MaximumCapabilityAgeSeconds > 86400 {
		return errors.New("platform profile capability boundary is invalid")
	}
	return nil
}

func PlatformProfileDigest(profile PlatformProfile) (string, error) {
	if err := ValidatePlatformProfile(profile); err != nil {
		return "", err
	}
	normalized := profile
	normalized.RequiredApplications = append([]PlatformApplicationExpectation(nil), profile.RequiredApplications...)
	sort.Slice(normalized.RequiredApplications, func(i, j int) bool {
		return normalized.RequiredApplications[i].Name < normalized.RequiredApplications[j].Name
	})
	return canonicalDigest(normalized)
}

func validatePlatformProfile(policy Policy, profile PlatformProfile) error {
	if err := ValidatePlatformProfile(profile); err != nil {
		return err
	}
	if profile.IntentRevision != policy.IntentRevision || profile.PlatformRevision != policy.PlatformRevision {
		return errors.New("platform profile identity differs from observation policy")
	}
	return nil
}

func validatePlatformSnapshotShape(snapshot PlatformSnapshot) error {
	if snapshot.Format != PlatformSnapshotFormat || snapshot.ObservedAt == "" || !validUID(snapshot.TargetClusterUID) || len(snapshot.Applications) > 20 {
		return errors.New("platform snapshot identity or size is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.ObservedAt); err != nil {
		return errors.New("platform snapshot observation time is invalid")
	}
	if err := validatePlatformApplications(snapshot.Applications); err != nil {
		return err
	}
	return ValidatePlatformCapabilityState(snapshot.Capability)
}

func validatePlatformApplicationSnapshotShape(snapshot PlatformApplicationSnapshot) error {
	if snapshot.Format != PlatformApplicationSnapshotFormat || snapshot.ObservedAt == "" || !validUID(snapshot.TargetClusterUID) || len(snapshot.Applications) > 20 {
		return errors.New("platform Application snapshot identity or size is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.ObservedAt); err != nil {
		return errors.New("platform Application snapshot observation time is invalid")
	}
	return validatePlatformApplications(snapshot.Applications)
}

func validatePlatformApplications(applications []PlatformApplicationState) error {
	for _, application := range applications {
		if !validDNSLabel(application.Name) || !validUID(application.UID) || application.ResourceVersion == "" || !validDigest(application.SpecDigest) {
			return errors.New("platform snapshot Application identity is invalid")
		}
		for _, revision := range []string{application.IntentRevision, application.PlatformRevision, application.ExecutionFixture} {
			if revision != "" && !validDigest(revision) {
				return errors.New("platform snapshot Application revision is malformed")
			}
		}
		if len(application.DesiredSourceRevision) > 128 || len(application.AppliedSourceRevision) > 128 || len(application.SyncStatus) > 64 || len(application.HealthStatus) > 64 {
			return errors.New("platform snapshot Application state is oversized")
		}
	}
	return nil
}

// ValidatePlatformCapabilityState checks the complete redaction-safe assertion
// including its self-independent semantic digest. It does not establish who
// produced the assertion; expected identities are supplied to the runner input
// loader from an independently verified execution boundary.
func ValidatePlatformCapabilityState(capability PlatformCapabilityState) error {
	if capability.Format != PlatformCapabilityFormat || capability.ObservedAt == "" || !validUID(capability.TargetClusterUID) {
		return errors.New("platform capability identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, capability.ObservedAt); err != nil {
		return errors.New("platform capability observation time is invalid")
	}
	for _, revision := range []string{capability.IntentRevision, capability.PlatformRevision, capability.ExecutionFixture, capability.ContractDigest, capability.ExecutableDigest, capability.EvidenceDigest} {
		if !validDigest(revision) {
			return errors.New("platform capability revision or evidence identity is invalid")
		}
	}
	expectedCapabilityDigest, err := PlatformCapabilityDigest(capability)
	if err != nil || capability.EvidenceDigest != expectedCapabilityDigest {
		return errors.New("platform capability evidence digest is invalid")
	}
	return nil
}

// PlatformCapabilityDigest binds the normalized capability statement without
// making its digest self-referential.
func PlatformCapabilityDigest(capability PlatformCapabilityState) (string, error) {
	value := capability
	value.EvidenceDigest = ""
	return canonicalDigest(value)
}

func evaluatePlatformState(policy Policy, profile PlatformProfile, snapshot PlatformSnapshot) (string, string, string) {
	status, reason, observedRevision := evaluatePlatformApplications(policy, profile, snapshot.TargetClusterUID, snapshot.Applications)
	if status != "True" {
		return status, reason, observedRevision
	}
	capability := snapshot.Capability
	if capability.TargetClusterUID != policy.TargetClusterUID || capability.IntentRevision != policy.IntentRevision || capability.PlatformRevision != policy.PlatformRevision || capability.ExecutionFixture != profile.ExecutionFixture || capability.ContractDigest != profile.CapabilityContractDigest || capability.ExecutableDigest != profile.CapabilityExecutableDigest {
		return "Unknown", "RevisionCorrelationUnproven", ""
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, snapshot.ObservedAt)
	capabilityAt, _ := time.Parse(time.RFC3339Nano, capability.ObservedAt)
	age := observedAt.Sub(capabilityAt)
	if age < 0 || age > time.Duration(profile.MaximumCapabilityAgeSeconds)*time.Second {
		return "Unknown", "PlatformCapabilityStale", policy.PlatformRevision
	}
	if !capability.Passed {
		return "False", "PlatformCapabilityFailed", policy.PlatformRevision
	}
	return "True", "PlatformReady", policy.PlatformRevision
}

func evaluatePlatformApplications(policy Policy, profile PlatformProfile, targetClusterUID string, applications []PlatformApplicationState) (string, string, string) {
	if targetClusterUID != policy.TargetClusterUID {
		return "Unknown", "RevisionCorrelationUnproven", ""
	}
	expected := make(map[string]string, len(profile.RequiredApplications))
	for _, application := range profile.RequiredApplications {
		expected[application.Name] = application.SpecDigest
	}
	seen := map[string]struct{}{}
	for _, application := range applications {
		specDigest, exists := expected[application.Name]
		if !exists || application.SpecDigest != specDigest {
			return "False", "PlatformApplicationIdentityMismatch", ""
		}
		if _, duplicate := seen[application.Name]; duplicate {
			return "False", "PlatformApplicationIdentityMismatch", ""
		}
		seen[application.Name] = struct{}{}
		if application.IntentRevision != policy.IntentRevision || application.PlatformRevision != policy.PlatformRevision || application.ExecutionFixture != profile.ExecutionFixture {
			return "Unknown", "RevisionCorrelationUnproven", ""
		}
		if application.DesiredSourceRevision == "" || application.AppliedSourceRevision != application.DesiredSourceRevision {
			return "Unknown", "PlatformConvergencePending", policy.PlatformRevision
		}
		if application.SyncStatus != "Synced" {
			return "Unknown", "PlatformConvergencePending", policy.PlatformRevision
		}
		if application.HealthStatus != "Healthy" {
			return "False", "PlatformHealthFailed", policy.PlatformRevision
		}
	}
	if len(seen) != len(expected) {
		return "Unknown", "PlatformApplicationMissing", ""
	}
	return "True", "PlatformApplicationsReady", policy.PlatformRevision
}

func sortPlatformApplications(applications []PlatformApplicationState) {
	sort.Slice(applications, func(i, j int) bool { return applications[i].Name < applications[j].Name })
}
