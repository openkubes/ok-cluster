package authorization

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const (
	StageFormat   = "ok147-stage-authorization/v1"
	StageFormatV2 = "ok147-stage-authorization/v2"
	StageAudience = "ok-cluster-staged-executor"

	maximumStageGrantBytes = 128 * 1024
	maximumPublicKeyBytes  = 4 * 1024
)

var (
	stageGrantIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,127}$`)
	stageDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// StagePayload is a single-use decision for exactly one mutating stage. It
// cannot authorize another stage, plan, Contract incarnation or authority.
type StagePayload struct {
	Audience           string             `json:"audience"`
	GrantID            string             `json:"grantId"`
	Decision           string             `json:"decision"`
	PlanDigest         string             `json:"planDigest"`
	ContractIdentity   contract.Identity  `json:"contractIdentity"`
	ContractRevision   string             `json:"contractRevision"`
	EnablementRevision string             `json:"enablementRevision"`
	PlatformRevision   string             `json:"platformRevision"`
	ExecutionFixture   string             `json:"executionFixture"`
	ExecutionAttempt   string             `json:"executionAttemptDigest,omitempty"`
	StageID            string             `json:"stageId"`
	StageOrder         int                `json:"stageOrder"`
	StageDigest        string             `json:"stageDigest"`
	Operation          string             `json:"operation"`
	Authority          string             `json:"authority"`
	Predecessors       []StagePredecessor `json:"predecessors"`
	NotBefore          string             `json:"notBefore"`
	NotAfter           string             `json:"notAfter"`
	MaxUses            int                `json:"maxUses"`
}

type StagePredecessor struct {
	StageID       string `json:"stageId"`
	OutcomeDigest string `json:"outcomeDigest"`
}

type stageEnvelope struct {
	Format    string       `json:"format"`
	Payload   StagePayload `json:"payload"`
	Signature signature    `json:"signature"`
}

type StageReceipt struct {
	Format              string `json:"format"`
	State               string `json:"state"`
	AuthorizationDigest string `json:"authorizationDigest"`
	GrantID             string `json:"grantId"`
	KeyID               string `json:"keyId"`
	PlanDigest          string `json:"planDigest"`
	StageID             string `json:"stageId"`
	StageDigest         string `json:"stageDigest"`
	Operation           string `json:"operation"`
	Authority           string `json:"authority"`
	PredecessorDigest   string `json:"predecessorDigest"`
	NotAfter            string `json:"notAfter"`
	MaxUses             int    `json:"maxUses"`
	ExecutionAttempt    string `json:"executionAttemptDigest,omitempty"`
}

type StageConsumptionBinding struct {
	AuthorizationDigest string
	GrantID             string
	KeyID               string
	PlanDigest          string
	StageID             string
	StageDigest         string
	Operation           string
	Authority           string
	PredecessorDigest   string
	ContractRevision    string
	NotBefore           string
	NotAfter            string
	ExecutionAttempt    string
}

type VerifiedStageGrant struct {
	receipt  StageReceipt
	binding  StageConsumptionBinding
	verified bool
}

func (grant VerifiedStageGrant) Receipt() StageReceipt { return grant.receipt }

func (grant VerifiedStageGrant) ConsumptionBinding() (StageConsumptionBinding, error) {
	if !grant.verified {
		return StageConsumptionBinding{}, errors.New("stage authorization was not produced by verification")
	}
	return grant.binding, nil
}

// BindStageGrant rechecks a verified grant against the exact next mutating
// stage and its verified direct predecessor receipts before ledger claim.
func BindStageGrant(grant VerifiedStageGrant, plan stageplan.Binding, expectedStageID string, expectedPredecessors []stagereceipt.Verified) (StageConsumptionBinding, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return StageConsumptionBinding{}, err
	}
	stage, stageDigest, err := plan.Stage(expectedStageID)
	if err != nil {
		return StageConsumptionBinding{}, err
	}
	if !stageplan.IsMutating(stage) {
		return StageConsumptionBinding{}, errors.New("read-only stage cannot bind a mutation grant")
	}
	_, predecessorDigest, err := verifiedStagePredecessors(expectedPredecessors, stage.Requires, plan.PlanDigest)
	if err != nil {
		return StageConsumptionBinding{}, err
	}
	if binding.PlanDigest != plan.PlanDigest || binding.StageID != stage.ID || binding.StageDigest != stageDigest || binding.Operation != stage.GrantOperation || binding.Authority != stage.Authority || binding.PredecessorDigest != predecessorDigest || binding.ContractRevision != plan.IntentRevision || binding.ExecutionAttempt != plan.ExecutionAttempt {
		return StageConsumptionBinding{}, errors.New("verified stage grant differs from the selected stage cursor")
	}
	return binding, nil
}

// LoadStage reads one bounded regular grant and trusted public-key file before
// performing the same in-memory verification as VerifyStage. Source paths are
// never retained in the verified grant or returned errors.
func LoadStage(grantPath, publicKeyPath string, plan stageplan.Binding, expectedStageID string, expectedPredecessors []stagereceipt.Verified, at time.Time) (VerifiedStageGrant, error) {
	raw, err := readStageAuthorizationFile(grantPath, maximumStageGrantBytes, "stage authorization")
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	publicKeyRaw, err := readStageAuthorizationFile(publicKeyPath, maximumPublicKeyBytes, "stage authorization public key")
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	return VerifyStage(raw, publicKeyRaw, plan, expectedStageID, expectedPredecessors, at)
}

// VerifyStage verifies a signature and binds it to one exact mutating stage
// from an already verified staged execution plan.
func VerifyStage(raw, publicKeyRaw []byte, plan stageplan.Binding, expectedStageID string, expectedPredecessors []stagereceipt.Verified, at time.Time) (VerifiedStageGrant, error) {
	stage, stageDigest, err := plan.Stage(expectedStageID)
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	if !stageplan.IsMutating(stage) {
		return VerifiedStageGrant{}, errors.New("read-only stages do not accept mutation grants")
	}
	var document stageEnvelope
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return VerifiedStageGrant{}, fmt.Errorf("decode stage authorization: %w", err)
	}
	if document.Format != StageFormat && document.Format != StageFormatV2 {
		return VerifiedStageGrant{}, fmt.Errorf("stage authorization format %q is not supported", document.Format)
	}
	if plan.Format == stageplan.BindingFormat && document.Format != StageFormat || plan.Format == stageplan.BindingFormatV2 && document.Format != StageFormatV2 {
		return VerifiedStageGrant{}, errors.New("stage authorization format differs from the staged plan")
	}
	publicKey, keyID, err := parsePublicKey(publicKeyRaw)
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	if document.Signature.Algorithm != "Ed25519" || document.Signature.KeyID != keyID {
		return VerifiedStageGrant{}, errors.New("stage authorization signature metadata is not accepted")
	}
	signatureBytes, err := base64.StdEncoding.Strict().DecodeString(document.Signature.Value)
	if err != nil {
		return VerifiedStageGrant{}, fmt.Errorf("decode stage authorization signature: %w", err)
	}
	signed, err := StageSigningBytes(document.Payload)
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	if !ed25519.Verify(publicKey, signed, signatureBytes) {
		return VerifiedStageGrant{}, errors.New("stage authorization signature verification failed")
	}
	predecessorDigest, err := verifyStagePayload(document.Payload, plan, stage, stageDigest, expectedPredecessors, at)
	if err != nil {
		return VerifiedStageGrant{}, err
	}
	receiptFormat := "ok147-stage-authorization-receipt/v1"
	if document.Format == StageFormatV2 {
		receiptFormat = "ok147-stage-authorization-receipt/v2"
	}
	receipt := StageReceipt{
		Format: receiptFormat, State: "VERIFIED",
		AuthorizationDigest: digest.SHA256(raw), GrantID: document.Payload.GrantID, KeyID: keyID,
		PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
		Operation: stage.GrantOperation, Authority: stage.Authority,
		PredecessorDigest: predecessorDigest,
		NotAfter:          document.Payload.NotAfter, MaxUses: document.Payload.MaxUses,
		ExecutionAttempt: document.Payload.ExecutionAttempt,
	}
	return VerifiedStageGrant{
		receipt: receipt,
		binding: StageConsumptionBinding{
			AuthorizationDigest: receipt.AuthorizationDigest, GrantID: receipt.GrantID, KeyID: keyID,
			PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority,
			PredecessorDigest: predecessorDigest,
			ContractRevision:  plan.IntentRevision, NotBefore: document.Payload.NotBefore, NotAfter: document.Payload.NotAfter,
			ExecutionAttempt: document.Payload.ExecutionAttempt,
		},
		verified: true,
	}, nil
}

func StageSigningBytes(payload StagePayload) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

func verifyStagePayload(payload StagePayload, plan stageplan.Binding, stage stageplan.Stage, stageDigest string, expectedPredecessors []stagereceipt.Verified, at time.Time) (string, error) {
	if payload.Audience != StageAudience || payload.Decision != "ALLOW" {
		return "", errors.New("stage authorization audience or decision is not accepted")
	}
	if !stageGrantIDPattern.MatchString(payload.GrantID) {
		return "", errors.New("stage authorization grantId is invalid")
	}
	if payload.PlanDigest != plan.PlanDigest || payload.ContractIdentity != plan.ContractIdentity || payload.ContractRevision != plan.IntentRevision || payload.EnablementRevision != plan.EnablementRevision || payload.PlatformRevision != plan.PlatformRevision || payload.ExecutionFixture != plan.ExecutionFixture {
		return "", errors.New("stage authorization plan or Contract bindings differ")
	}
	if payload.ExecutionAttempt != plan.ExecutionAttempt {
		return "", errors.New("stage authorization execution attempt differs")
	}
	if payload.StageID != stage.ID || payload.StageOrder != stage.Order || payload.StageDigest != stageDigest || payload.Operation != stage.GrantOperation || payload.Authority != stage.Authority {
		return "", errors.New("stage authorization does not bind the exact stage")
	}
	predecessorDigest, err := verifyStagePredecessors(payload.Predecessors, expectedPredecessors, stage.Requires, plan.PlanDigest)
	if err != nil {
		return "", err
	}
	if payload.MaxUses != 1 {
		return "", errors.New("stage authorization must declare exactly one use")
	}
	notBefore, err := time.Parse(time.RFC3339, payload.NotBefore)
	if err != nil {
		return "", fmt.Errorf("stage authorization notBefore: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, payload.NotAfter)
	if err != nil {
		return "", fmt.Errorf("stage authorization notAfter: %w", err)
	}
	if !notAfter.After(notBefore) || notAfter.Sub(notBefore) > MaximumWindow {
		return "", errors.New("stage authorization time window is invalid")
	}
	if at.Before(notBefore) || !at.Before(notAfter) {
		return "", errors.New("stage authorization is not active at the evaluation time")
	}
	return predecessorDigest, nil
}

func verifyStagePredecessors(payload []StagePredecessor, expected []stagereceipt.Verified, required []string, planDigest string) (string, error) {
	if payload == nil || expected == nil || len(payload) != len(required) || len(expected) != len(required) {
		return "", errors.New("stage authorization predecessor set is incomplete")
	}
	bindings, predecessorDigest, err := verifiedStagePredecessors(expected, required, planDigest)
	if err != nil {
		return "", err
	}
	for index := range bindings {
		if payload[index] != bindings[index] || !stageDigestPattern.MatchString(payload[index].OutcomeDigest) {
			return "", errors.New("stage authorization predecessor evidence differs")
		}
	}
	return predecessorDigest, nil
}

func verifiedStagePredecessors(expected []stagereceipt.Verified, required []string, planDigest string) ([]StagePredecessor, string, error) {
	if expected == nil || len(expected) != len(required) {
		return nil, "", errors.New("stage authorization predecessor set is incomplete")
	}
	bindings := make([]StagePredecessor, len(expected))
	for index, stageID := range required {
		receipt, err := expected[index].Receipt()
		if err != nil {
			return nil, "", err
		}
		receiptDigest, err := expected[index].Digest()
		if err != nil {
			return nil, "", err
		}
		bindings[index] = StagePredecessor{StageID: receipt.StageID, OutcomeDigest: receiptDigest}
		if receipt.PlanDigest != planDigest || receipt.State != "SUCCEEDED" || bindings[index].StageID != stageID || !stageDigestPattern.MatchString(receiptDigest) {
			return nil, "", errors.New("stage authorization predecessor evidence differs")
		}
	}
	raw, err := json.Marshal(bindings)
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", err
	}
	return bindings, digest.SHA256(canonical), nil
}

func readStageAuthorizationFile(path string, maximum int64, label string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s path is required", label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s", label)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s metadata is invalid", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s", label)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("read bounded %s", label)
	}
	return raw, nil
}
