// Package stageplan verifies the complete bounded execution sequence without
// rendering manifests, opening credentials, contacting Kubernetes, or granting
// authority. It binds each stage to independently produced immutable inputs.
package stageplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	Format           = "ok147-staged-execution-plan/v1"
	BindingFormat    = "ok147-verified-staged-execution-plan/v1"
	maximumPlanBytes = 128 * 1024
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,127}$`)
)

// Expected is supplied from already verified Contract, fixture and topology
// inputs. It prevents a plan file from selecting different authority planes.
type Expected struct {
	ContractIdentity        contract.Identity
	IntentRevision          string
	EnablementRevision      string
	PlatformRevision        string
	ExecutionFixture        string
	InfrastructureAuthority string
	ManagementAuthority     string
	GitOpsAuthority         string
}

type Authorities struct {
	Infrastructure       string `json:"infrastructure"`
	Management           string `json:"management"`
	GitOps               string `json:"gitOps"`
	WorkloadIdentityMode string `json:"workloadIdentityMode"`
	RunnerIdentityMode   string `json:"runnerIdentityMode"`
}

// Input binds a stage to an immutable, externally produced artifact. The
// runner may consume it, but this package never interprets or creates it.
type Input struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Stage struct {
	ID             string   `json:"id"`
	Order          int      `json:"order"`
	Kind           string   `json:"kind"`
	Authority      string   `json:"authority"`
	GrantOperation string   `json:"grantOperation,omitempty"`
	Requires       []string `json:"requires"`
	Inputs         []Input  `json:"inputs"`
}

type document struct {
	Format             string            `json:"format"`
	ContractIdentity   contract.Identity `json:"contractIdentity"`
	IntentRevision     string            `json:"intentRevision"`
	EnablementRevision string            `json:"enablementRevision"`
	PlatformRevision   string            `json:"platformRevision"`
	ExecutionFixture   string            `json:"executionFixture"`
	AuthorizationState string            `json:"authorizationState"`
	Authorities        Authorities       `json:"authorities"`
	Stages             []Stage           `json:"stages"`
}

// Binding is the immutable, redaction-safe result of successful verification.
// It carries no source path, raw manifests, credentials or authorization.
type Binding struct {
	Format              string            `json:"format"`
	PlanDigest          string            `json:"planDigest"`
	ContractIdentity    contract.Identity `json:"contractIdentity"`
	IntentRevision      string            `json:"intentRevision"`
	EnablementRevision  string            `json:"enablementRevision"`
	PlatformRevision    string            `json:"platformRevision"`
	ExecutionFixture    string            `json:"executionFixture"`
	Authorities         Authorities       `json:"authorities"`
	Stages              []Stage           `json:"stages"`
	verified            bool
	verifiedDigest      string
	verifiedIdentity    contract.Identity
	verifiedRevisions   [4]string
	verifiedAuthorities Authorities
	stageDigests        map[string]string
}

type stageRule struct {
	id             string
	kind           string
	authority      string
	grantOperation string
	requires       []string
}

var requiredSequence = []stageRule{
	{id: "provider-prerequisites", kind: "Submission", authority: "infrastructure", grantOperation: "CreateProviderPrerequisites"},
	{id: "cluster-lifecycle", kind: "Submission", authority: "management", grantOperation: "CreateCluster", requires: []string{"provider-prerequisites"}},
	{id: "lifecycle-observation", kind: "Observation", authority: "management", requires: []string{"cluster-lifecycle"}},
	{id: "enablement", kind: "Submission", authority: "management", grantOperation: "CreateEnablement", requires: []string{"lifecycle-observation"}},
	{id: "network-observation", kind: "Observation", authority: "workload", requires: []string{"enablement"}},
	{id: "runtime-binding", kind: "Binding", authority: "runner", requires: []string{"network-observation"}},
	{id: "target-access", kind: "Submission", authority: "workload", grantOperation: "CreateTargetAccess", requires: []string{"runtime-binding"}},
	{id: "target-credential", kind: "Credential", authority: "workload", grantOperation: "IssueTargetCredential", requires: []string{"target-access"}},
	{id: "target-registration", kind: "Submission", authority: "gitops", grantOperation: "RegisterTarget", requires: []string{"target-credential"}},
	{id: "platform-applications", kind: "Submission", authority: "gitops", grantOperation: "CreatePlatformApplications", requires: []string{"target-registration"}},
	{id: "platform-observation", kind: "Observation", authority: "gitops", requires: []string{"platform-applications"}},
	{id: "aggregate-evidence", kind: "Evaluation", authority: "runner", requires: []string{"platform-observation"}},
}

// Load reads and verifies one bounded strict-JSON plan.
func Load(path string, expected Expected) (Binding, error) {
	if path == "" {
		return Binding{}, errors.New("staged execution plan path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Binding{}, fmt.Errorf("inspect staged execution plan: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumPlanBytes {
		return Binding{}, errors.New("staged execution plan metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return Binding{}, fmt.Errorf("open staged execution plan: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumPlanBytes+1))
	if err != nil || len(raw) > maximumPlanBytes {
		return Binding{}, errors.New("read bounded staged execution plan")
	}
	return Verify(raw, expected)
}

// Verify validates plan content already held in memory. It is exported so a
// caller can verify a plan delivered by a bounded non-filesystem transport.
func Verify(raw []byte, expected Expected) (Binding, error) {
	if err := ValidateExpected(expected); err != nil {
		return Binding{}, err
	}
	var source document
	if err := jsonstrict.Decode(raw, &source); err != nil {
		return Binding{}, fmt.Errorf("decode staged execution plan: %w", err)
	}
	if source.Format != Format {
		return Binding{}, fmt.Errorf("staged execution plan format %q is not supported", source.Format)
	}
	if source.AuthorizationState != "NO-GO" {
		return Binding{}, errors.New("staged execution plan must remain non-authorizing (authorizationState NO-GO)")
	}
	if source.IntentRevision != expected.IntentRevision || source.EnablementRevision != expected.EnablementRevision || source.PlatformRevision != expected.PlatformRevision || source.ExecutionFixture != expected.ExecutionFixture {
		return Binding{}, errors.New("staged execution plan revisions or fixture differ from verified inputs")
	}
	if source.ContractIdentity != expected.ContractIdentity {
		return Binding{}, errors.New("staged execution plan Contract identity differs from verified input")
	}
	if source.Authorities.Infrastructure != expected.InfrastructureAuthority || source.Authorities.Management != expected.ManagementAuthority || source.Authorities.GitOps != expected.GitOpsAuthority {
		return Binding{}, errors.New("staged execution plan authority identities differ from verified topology")
	}
	if source.Authorities.WorkloadIdentityMode != "capi-cluster-uid/v1" || source.Authorities.RunnerIdentityMode != "bounded-job/v1" {
		return Binding{}, errors.New("staged execution plan uses an unsupported dynamic authority mode")
	}
	if err := validateStages(source.Stages); err != nil {
		return Binding{}, err
	}
	planDigest, err := canonicalDigest(source)
	if err != nil {
		return Binding{}, err
	}
	stageDigests := make(map[string]string, len(source.Stages))
	for _, stage := range source.Stages {
		stageDigest, err := canonicalDigest(stage)
		if err != nil {
			return Binding{}, err
		}
		stageDigests[stage.ID] = stageDigest
	}
	return Binding{
		Format: BindingFormat, PlanDigest: planDigest,
		ContractIdentity: source.ContractIdentity,
		IntentRevision:   source.IntentRevision, EnablementRevision: source.EnablementRevision,
		PlatformRevision: source.PlatformRevision, ExecutionFixture: source.ExecutionFixture,
		Authorities: source.Authorities, Stages: cloneStages(source.Stages),
		verified: true, verifiedDigest: planDigest, verifiedIdentity: source.ContractIdentity,
		verifiedRevisions:   [4]string{source.IntentRevision, source.EnablementRevision, source.PlatformRevision, source.ExecutionFixture},
		verifiedAuthorities: source.Authorities, stageDigests: stageDigests,
	}, nil
}

// ValidateExpected checks independently supplied Contract, fixture and
// topology identities without loading or accepting a staged plan.
func ValidateExpected(expected Expected) error {
	if expected.ContractIdentity.Name == "" || expected.ContractIdentity.Namespace == "" {
		return errors.New("expected Contract identity is incomplete")
	}
	for label, value := range map[string]string{
		"intent revision": expected.IntentRevision, "enablement revision": expected.EnablementRevision,
		"platform revision": expected.PlatformRevision, "execution fixture": expected.ExecutionFixture,
	} {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("expected %s is invalid", label)
		}
	}
	for label, value := range map[string]string{
		"infrastructure authority": expected.InfrastructureAuthority,
		"management authority":     expected.ManagementAuthority, "GitOps authority": expected.GitOpsAuthority,
	} {
		if !namePattern.MatchString(value) {
			return fmt.Errorf("expected %s is invalid", label)
		}
	}
	if expected.InfrastructureAuthority == expected.ManagementAuthority || expected.InfrastructureAuthority == expected.GitOpsAuthority || expected.ManagementAuthority == expected.GitOpsAuthority {
		return errors.New("infrastructure, management, and GitOps authorities must be distinct")
	}
	return nil
}

func validateStages(stages []Stage) error {
	if len(stages) != len(requiredSequence) {
		return fmt.Errorf("staged execution plan has %d stages, expected %d", len(stages), len(requiredSequence))
	}
	for index, rule := range requiredSequence {
		stage := stages[index]
		if stage.Order != index+1 || stage.ID != rule.id || stage.Kind != rule.kind || stage.Authority != rule.authority || stage.GrantOperation != rule.grantOperation || !equalStrings(stage.Requires, rule.requires) {
			return fmt.Errorf("stage %d does not match the required bounded sequence", index+1)
		}
		if len(stage.Inputs) == 0 {
			return fmt.Errorf("stage %s has no immutable input bindings", stage.ID)
		}
		previous := ""
		for _, input := range stage.Inputs {
			if !namePattern.MatchString(input.Name) || !digestPattern.MatchString(input.Digest) {
				return fmt.Errorf("stage %s has an invalid input binding", stage.ID)
			}
			if previous != "" && input.Name <= previous {
				return fmt.Errorf("stage %s input bindings are not uniquely sorted", stage.ID)
			}
			previous = input.Name
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneStages(stages []Stage) []Stage {
	result := make([]Stage, len(stages))
	for index, stage := range stages {
		result[index] = stage
		if stage.Requires != nil {
			result[index].Requires = append([]string{}, stage.Requires...)
		}
		if stage.Inputs != nil {
			result[index].Inputs = append([]Input{}, stage.Inputs...)
		}
	}
	return result
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

// InputNames returns a stable copy useful for redacted plan evidence.
func InputNames(stage Stage) []string {
	names := make([]string, 0, len(stage.Inputs))
	for _, input := range stage.Inputs {
		names = append(names, input.Name)
	}
	sort.Strings(names)
	return names
}

// IsMutating reports whether a stage needs its own content-bound grant.
func IsMutating(stage Stage) bool { return strings.TrimSpace(stage.GrantOperation) != "" }

// Stage returns one stage and its canonical semantic digest after rechecking
// that the in-memory binding still represents the originally verified plan.
func (binding Binding) Stage(id string) (Stage, string, error) {
	if !binding.verified || binding.Format != BindingFormat || binding.PlanDigest != binding.verifiedDigest || !digestPattern.MatchString(binding.PlanDigest) {
		return Stage{}, "", errors.New("verified staged execution binding is required")
	}
	if binding.ContractIdentity != binding.verifiedIdentity || [4]string{binding.IntentRevision, binding.EnablementRevision, binding.PlatformRevision, binding.ExecutionFixture} != binding.verifiedRevisions || binding.Authorities != binding.verifiedAuthorities {
		return Stage{}, "", errors.New("staged execution top-level binding changed after verification")
	}
	if err := validateStages(binding.Stages); err != nil {
		return Stage{}, "", fmt.Errorf("revalidate staged execution binding: %w", err)
	}
	for _, stage := range binding.Stages {
		if stage.ID == id {
			stageDigest, err := canonicalDigest(stage)
			if err != nil || stageDigest != binding.stageDigests[id] {
				return Stage{}, "", errors.New("staged execution stage binding changed after verification")
			}
			return cloneStages([]Stage{stage})[0], stageDigest, nil
		}
	}
	return Stage{}, "", fmt.Errorf("stage %q is not part of the verified execution plan", id)
}

// RequireInput rechecks that one exact immutable artifact identity is bound to
// the selected verified stage. It does not interpret or load that artifact.
func (binding Binding) RequireInput(stageID, name, expectedDigest string) error {
	stage, _, err := binding.Stage(stageID)
	if err != nil {
		return err
	}
	if !namePattern.MatchString(name) || !digestPattern.MatchString(expectedDigest) {
		return errors.New("required staged execution input identity is invalid")
	}
	for _, input := range stage.Inputs {
		if input.Name == name {
			if input.Digest != expectedDigest {
				return errors.New("staged execution input digest differs from verified artifact")
			}
			return nil
		}
	}
	return errors.New("staged execution plan does not bind the required artifact")
}
