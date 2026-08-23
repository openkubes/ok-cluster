// Package stageattempt verifies the redaction-safe identity of one bounded
// execution attempt. An attempt is neither desired Cluster state nor a grant.
package stageattempt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	Format        = "ok147-execution-attempt/v1"
	ReceiptFormat = "ok147-verified-execution-attempt/v1"
	Mode          = "create-converge-observe/v1"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,127}$`)
	imagePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$`)
)

// Document contains only reviewed, redaction-safe identities. In particular,
// it never carries a credential, endpoint, raw manifest or command.
type Document struct {
	Format                   string `json:"format"`
	AttemptID                string `json:"attemptId"`
	SourceFixtureDigest      string `json:"sourceFixtureDigest"`
	SourcePlanSemanticDigest string `json:"sourcePlanSemanticDigest"`
	RunnerImage              string `json:"runnerImage"`
	ActivationPackageDigest  string `json:"activationPackageDigest"`
	Mode                     string `json:"mode"`
	PredecessorAttemptDigest string `json:"predecessorAttemptDigest,omitempty"`
	StoppedEvidenceDigest    string `json:"stoppedEvidenceDigest,omitempty"`
	DecisionWindowDigest     string `json:"decisionWindowDigest"`
	MaxAttempts              int    `json:"maxAttempts"`
}

// Expected is independently supplied from reviewed fixture, runner,
// activation and stopped-evidence checkpoints.
type Expected struct {
	AttemptID                string
	SourceFixtureDigest      string
	SourcePlanSemanticDigest string
	RunnerImage              string
	ActivationPackageDigest  string
	PredecessorAttemptDigest string
	StoppedEvidenceDigest    string
	DecisionWindowDigest     string
}

// Receipt is safe to retain publicly. It grants no execution authority.
type Receipt struct {
	Format                  string `json:"format"`
	State                   string `json:"state"`
	ExecutionAttemptDigest  string `json:"executionAttemptDigest"`
	SourceFixtureDigest     string `json:"sourceFixtureDigest"`
	SourcePlanDigest        string `json:"sourcePlanSemanticDigest"`
	RunnerImage             string `json:"runnerImage"`
	ActivationPackageDigest string `json:"activationPackageDigest"`
	Mode                    string `json:"mode"`
	RecoveryBound           bool   `json:"recoveryBound"`
	MaxAttempts             int    `json:"maxAttempts"`
	MutationAllowed         bool   `json:"mutationAllowed"`
}

// Verify accepts only the exact independently expected attempt and returns
// its canonical semantic identity.
func Verify(raw []byte, expected Expected) (Receipt, error) {
	if err := validateExpected(expected); err != nil {
		return Receipt{}, err
	}
	var document Document
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return Receipt{}, fmt.Errorf("decode execution attempt: %w", err)
	}
	if err := validateDocument(document); err != nil {
		return Receipt{}, err
	}
	if document.AttemptID != expected.AttemptID || document.SourceFixtureDigest != expected.SourceFixtureDigest ||
		document.SourcePlanSemanticDigest != expected.SourcePlanSemanticDigest || document.RunnerImage != expected.RunnerImage ||
		document.ActivationPackageDigest != expected.ActivationPackageDigest || document.PredecessorAttemptDigest != expected.PredecessorAttemptDigest ||
		document.StoppedEvidenceDigest != expected.StoppedEvidenceDigest || document.DecisionWindowDigest != expected.DecisionWindowDigest {
		return Receipt{}, errors.New("execution attempt differs from independently verified inputs")
	}
	canonical, err := canonicalJSON(document)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{
		Format: ReceiptFormat, State: "VERIFIED", ExecutionAttemptDigest: digest.SHA256(canonical),
		SourceFixtureDigest: document.SourceFixtureDigest, SourcePlanDigest: document.SourcePlanSemanticDigest,
		RunnerImage: document.RunnerImage, ActivationPackageDigest: document.ActivationPackageDigest,
		Mode: document.Mode, RecoveryBound: document.PredecessorAttemptDigest != "" || document.StoppedEvidenceDigest != "", MaxAttempts: document.MaxAttempts,
		MutationAllowed: false,
	}, nil
}

func validateExpected(expected Expected) error {
	if !namePattern.MatchString(expected.AttemptID) || !digestPattern.MatchString(expected.SourceFixtureDigest) ||
		!digestPattern.MatchString(expected.SourcePlanSemanticDigest) || !imagePattern.MatchString(expected.RunnerImage) ||
		!digestPattern.MatchString(expected.ActivationPackageDigest) || !digestPattern.MatchString(expected.DecisionWindowDigest) {
		return errors.New("expected execution attempt identity is invalid")
	}
	for _, value := range []string{expected.PredecessorAttemptDigest, expected.StoppedEvidenceDigest} {
		if value != "" && !digestPattern.MatchString(value) {
			return errors.New("expected recovery attempt identity is invalid")
		}
	}
	return nil
}

func validateDocument(document Document) error {
	if document.Format != Format || document.Mode != Mode || document.MaxAttempts != 1 ||
		!namePattern.MatchString(document.AttemptID) || !digestPattern.MatchString(document.SourceFixtureDigest) ||
		!digestPattern.MatchString(document.SourcePlanSemanticDigest) || !imagePattern.MatchString(document.RunnerImage) ||
		!digestPattern.MatchString(document.ActivationPackageDigest) || !digestPattern.MatchString(document.DecisionWindowDigest) {
		return errors.New("execution attempt identity is invalid")
	}
	for _, value := range []string{document.PredecessorAttemptDigest, document.StoppedEvidenceDigest} {
		if value != "" && !digestPattern.MatchString(value) {
			return errors.New("execution attempt recovery identity is invalid")
		}
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode execution attempt")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, errors.New("decode execution attempt identity")
	}
	canonical, err := contract.JCS(generic)
	if err != nil {
		return nil, errors.New("canonicalize execution attempt")
	}
	return canonical, nil
}
