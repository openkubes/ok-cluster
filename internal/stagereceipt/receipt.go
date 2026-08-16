// Package stagereceipt creates and verifies the immutable evidence chain shared
// by mutating and read-only stages. It performs no stage work itself.
package stagereceipt

import (
	"bytes"
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
)

const (
	Format              = "ok147-stage-receipt/v1"
	maximumReceiptBytes = 128 * 1024
)

var receiptDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Predecessor struct {
	StageID       string `json:"stageId"`
	ReceiptDigest string `json:"receiptDigest"`
}

// Receipt contains only redaction-safe identities and evidence digests.
type Receipt struct {
	Format                 string            `json:"format"`
	PlanDigest             string            `json:"planDigest"`
	ContractIdentity       contract.Identity `json:"contractIdentity"`
	ContractRevision       string            `json:"contractRevision"`
	EnablementRevision     string            `json:"enablementRevision"`
	PlatformRevision       string            `json:"platformRevision"`
	ExecutionFixture       string            `json:"executionFixture"`
	StageID                string            `json:"stageId"`
	StageOrder             int               `json:"stageOrder"`
	StageDigest            string            `json:"stageDigest"`
	Kind                   string            `json:"kind"`
	Authority              string            `json:"authority"`
	Operation              string            `json:"operation,omitempty"`
	Predecessors           []Predecessor     `json:"predecessors"`
	State                  string            `json:"state"`
	MutationState          string            `json:"mutationState"`
	OperationOutcomeDigest string            `json:"operationOutcomeDigest,omitempty"`
	EvidenceDigest         string            `json:"evidenceDigest"`
	CompletedAt            string            `json:"completedAt"`
}

// Verified can only be produced by New, Verify or Load. It retains canonical
// bytes so later links cannot observe caller mutation of a Receipt copy.
type Verified struct {
	receipt  Receipt
	digest   string
	raw      []byte
	verified bool
}

// New builds a receipt only after all direct predecessor receipts have been
// verified, completed successfully and matched to the same staged plan.
func New(plan stageplan.Binding, stageID string, predecessors []Verified, state, mutationState, operationOutcomeDigest, evidenceDigest string, completedAt time.Time) (Verified, error) {
	stage, stageDigest, err := plan.Stage(stageID)
	if err != nil {
		return Verified{}, err
	}
	links, err := verifiedLinks(plan, stage, predecessors, completedAt)
	if err != nil {
		return Verified{}, err
	}
	receipt := Receipt{
		Format: Format, PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity,
		ContractRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Kind: stage.Kind,
		Authority: stage.Authority, Operation: stage.GrantOperation, Predecessors: links,
		State: state, MutationState: mutationState, OperationOutcomeDigest: operationOutcomeDigest,
		EvidenceDigest: evidenceDigest, CompletedAt: completedAt.UTC().Format(time.RFC3339Nano),
	}
	return verifyReceipt(receipt, plan, predecessors)
}

// Verify accepts only canonical receipt bytes with an independently supplied
// expected digest and rechecks the complete direct predecessor chain.
func Verify(raw []byte, expectedDigest string, plan stageplan.Binding, predecessors []Verified) (Verified, error) {
	if !receiptDigestPattern.MatchString(expectedDigest) {
		return Verified{}, errors.New("expected stage receipt digest is invalid")
	}
	var receipt Receipt
	if err := jsonstrict.Decode(raw, &receipt); err != nil {
		return Verified{}, fmt.Errorf("decode stage receipt: %w", err)
	}
	verified, err := verifyReceipt(receipt, plan, predecessors)
	if err != nil {
		return Verified{}, err
	}
	if !bytes.Equal(raw, verified.raw) {
		return Verified{}, errors.New("stage receipt is not canonical or was modified")
	}
	if verified.digest != expectedDigest {
		return Verified{}, errors.New("stage receipt digest differs from expected identity")
	}
	return verified, nil
}

// Load reads one bounded, non-symlink receipt before verifying it.
func Load(path, expectedDigest string, plan stageplan.Binding, predecessors []Verified) (Verified, error) {
	if path == "" {
		return Verified{}, errors.New("stage receipt path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Verified{}, fmt.Errorf("inspect stage receipt: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumReceiptBytes {
		return Verified{}, errors.New("stage receipt metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return Verified{}, fmt.Errorf("open stage receipt: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumReceiptBytes+1))
	if err != nil || len(raw) > maximumReceiptBytes {
		return Verified{}, errors.New("read bounded stage receipt")
	}
	return Verify(raw, expectedDigest, plan, predecessors)
}

func (verified Verified) Receipt() (Receipt, error) {
	if !verified.verified {
		return Receipt{}, errors.New("stage receipt was not produced by verification")
	}
	receipt := verified.receipt
	receipt.Predecessors = append([]Predecessor{}, verified.receipt.Predecessors...)
	return receipt, nil
}

func (verified Verified) Digest() (string, error) {
	if !verified.verified || !receiptDigestPattern.MatchString(verified.digest) {
		return "", errors.New("stage receipt was not produced by verification")
	}
	return verified.digest, nil
}

func (verified Verified) Bytes() ([]byte, error) {
	if !verified.verified || len(verified.raw) == 0 {
		return nil, errors.New("stage receipt was not produced by verification")
	}
	return append([]byte(nil), verified.raw...), nil
}

func verifyReceipt(receipt Receipt, plan stageplan.Binding, predecessors []Verified) (Verified, error) {
	stage, stageDigest, err := plan.Stage(receipt.StageID)
	if err != nil {
		return Verified{}, err
	}
	if receipt.Format != Format || receipt.PlanDigest != plan.PlanDigest || receipt.ContractIdentity != plan.ContractIdentity || receipt.ContractRevision != plan.IntentRevision || receipt.EnablementRevision != plan.EnablementRevision || receipt.PlatformRevision != plan.PlatformRevision || receipt.ExecutionFixture != plan.ExecutionFixture {
		return Verified{}, errors.New("stage receipt plan or Contract identity differs")
	}
	if receipt.StageOrder != stage.Order || receipt.StageDigest != stageDigest || receipt.Kind != stage.Kind || receipt.Authority != stage.Authority || receipt.Operation != stage.GrantOperation {
		return Verified{}, errors.New("stage receipt does not bind the exact stage")
	}
	completedAt, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
	if err != nil {
		return Verified{}, errors.New("stage receipt completion time is invalid")
	}
	expectedLinks, err := verifiedLinks(plan, stage, predecessors, completedAt)
	if err != nil {
		return Verified{}, err
	}
	if !equalLinks(receipt.Predecessors, expectedLinks) {
		return Verified{}, errors.New("stage receipt predecessor chain differs")
	}
	if !allowed(receipt.State, "SUCCEEDED", "FAILED", "STOPPED") || !receiptDigestPattern.MatchString(receipt.EvidenceDigest) {
		return Verified{}, errors.New("stage receipt outcome or evidence digest is invalid")
	}
	if stageplan.IsMutating(stage) {
		if !allowed(receipt.MutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") || !receiptDigestPattern.MatchString(receipt.OperationOutcomeDigest) {
			return Verified{}, errors.New("mutating stage receipt lacks a valid operation outcome")
		}
		if receipt.State == "SUCCEEDED" && receipt.MutationState != "ATTEMPTED" {
			return Verified{}, errors.New("successful mutating stage did not attempt mutation")
		}
	} else if receipt.MutationState != "NOT_APPLICABLE" || receipt.OperationOutcomeDigest != "" {
		return Verified{}, errors.New("read-only stage receipt contains mutation state")
	}
	raw, receiptDigest, err := canonicalReceipt(receipt)
	if err != nil {
		return Verified{}, err
	}
	return Verified{receipt: receipt, digest: receiptDigest, raw: raw, verified: true}, nil
}

func verifiedLinks(plan stageplan.Binding, stage stageplan.Stage, predecessors []Verified, completedAt time.Time) ([]Predecessor, error) {
	if predecessors == nil || len(predecessors) != len(stage.Requires) {
		return nil, errors.New("stage receipt predecessor set is incomplete")
	}
	links := make([]Predecessor, len(predecessors))
	for index, predecessor := range predecessors {
		receipt, err := predecessor.Receipt()
		if err != nil {
			return nil, err
		}
		predecessorDigest, err := predecessor.Digest()
		if err != nil {
			return nil, err
		}
		if receipt.PlanDigest != plan.PlanDigest || receipt.StageID != stage.Requires[index] || receipt.State != "SUCCEEDED" || receipt.StageOrder >= stage.Order {
			return nil, errors.New("stage receipt predecessor is foreign, unsuccessful or out of order")
		}
		predecessorCompletedAt, err := time.Parse(time.RFC3339Nano, receipt.CompletedAt)
		if err != nil || completedAt.Before(predecessorCompletedAt) {
			return nil, errors.New("stage receipt completion precedes its predecessor")
		}
		links[index] = Predecessor{StageID: receipt.StageID, ReceiptDigest: predecessorDigest}
	}
	return links, nil
}

func canonicalReceipt(receipt Receipt) ([]byte, string, error) {
	raw, err := json.Marshal(receipt)
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
	return canonical, digest.SHA256(canonical), nil
}

func equalLinks(left, right []Predecessor) bool {
	if left == nil || right == nil || len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func allowed(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
