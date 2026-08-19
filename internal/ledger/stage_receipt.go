package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const (
	stageReceiptSlotFormat        = "ok147-stage-receipt-slot/v1"
	stageReceiptAttemptSlotFormat = "ok147-stage-receipt-attempt-slot/v1"
)

var ErrStageReceiptConflict = errors.New("a different stage receipt already occupies the immutable slot")

// StoreStageReceipt persists one verified receipt without replacing a prior
// attempt. The first receipt occupies the deterministic stage slot for legacy
// crash inspection; a different retry receipt occupies a digest-addressed
// immutable attempt slot. Exact replays are idempotent in either slot.
func (ledger *Ledger) StoreStageReceipt(ctx context.Context, plan stageplan.Binding, verified stagereceipt.Verified, predecessors []stagereceipt.Verified) (string, error) {
	receipt, err := verified.Receipt()
	if err != nil {
		return "", err
	}
	raw, err := verified.Bytes()
	if err != nil {
		return "", err
	}
	receiptDigest, err := verified.Digest()
	if err != nil {
		return "", err
	}
	if _, err := stagereceipt.Verify(raw, receiptDigest, plan, predecessors); err != nil {
		return "", fmt.Errorf("verify stage receipt before persistence: %w", err)
	}
	key, err := stageReceiptKey(plan, receipt.StageID)
	if err != nil {
		return "", err
	}
	if err := ledger.store.Create(ctx, "stage-receipts", key, raw); err == nil {
		return receiptDigest, nil
	} else if !errors.Is(err, ErrRecordExists) {
		return "", fmt.Errorf("write immutable stage receipt: %w", err)
	}
	existing, err := ledger.store.Get(ctx, "stage-receipts", key)
	if err != nil {
		return "", fmt.Errorf("read existing stage receipt: %w", err)
	}
	if bytes.Equal(existing, raw) {
		if _, err := stagereceipt.Verify(existing, receiptDigest, plan, predecessors); err != nil {
			return "", fmt.Errorf("verify existing stage receipt: %w", err)
		}
		return receiptDigest, nil
	}
	attemptKey, err := stageReceiptAttemptKey(plan, receipt.StageID, receiptDigest)
	if err != nil {
		return "", err
	}
	if err := ledger.store.Create(ctx, "stage-receipts", attemptKey, raw); err == nil {
		return receiptDigest, nil
	} else if !errors.Is(err, ErrRecordExists) {
		return "", fmt.Errorf("write immutable retry stage receipt: %w", err)
	}
	attempt, err := ledger.store.Get(ctx, "stage-receipts", attemptKey)
	if err != nil {
		return "", fmt.Errorf("read existing retry stage receipt: %w", err)
	}
	if !bytes.Equal(attempt, raw) {
		return "", ErrStageReceiptConflict
	}
	if _, err := stagereceipt.Verify(attempt, receiptDigest, plan, predecessors); err != nil {
		return "", fmt.Errorf("verify existing retry stage receipt: %w", err)
	}
	return receiptDigest, nil
}

// InspectStageReceipt reads the deterministic immutable slot and fully
// verifies any existing receipt against the supplied plan and predecessor
// chain. It is intended for crash-safe read-only stage replay, where the
// process may have terminated after persistence but before returning a digest.
func (ledger *Ledger) InspectStageReceipt(ctx context.Context, plan stageplan.Binding, stageID string, predecessors []stagereceipt.Verified) (stagereceipt.Verified, bool, error) {
	key, err := stageReceiptKey(plan, stageID)
	if err != nil {
		return stagereceipt.Verified{}, false, err
	}
	raw, err := ledger.store.Get(ctx, "stage-receipts", key)
	if errors.Is(err, ErrRecordNotFound) {
		return stagereceipt.Verified{}, false, nil
	}
	if err != nil {
		return stagereceipt.Verified{}, false, fmt.Errorf("read immutable stage receipt: %w", err)
	}
	verified, err := stagereceipt.Verify(raw, digest.SHA256(raw), plan, predecessors)
	if err != nil {
		return stagereceipt.Verified{}, false, fmt.Errorf("verify immutable stage receipt: %w", err)
	}
	receipt, err := verified.Receipt()
	if err != nil || receipt.StageID != stageID {
		return stagereceipt.Verified{}, false, errors.New("immutable stage receipt occupies a different stage")
	}
	return verified, true, nil
}

// LoadStageReceipt requires an independently supplied receipt identity. It
// first checks the legacy deterministic slot, then the digest-addressed retry
// slot. It never lists or chooses a latest attempt.
func (ledger *Ledger) LoadStageReceipt(ctx context.Context, plan stageplan.Binding, stageID, expectedDigest string, predecessors []stagereceipt.Verified) (stagereceipt.Verified, error) {
	key, err := stageReceiptKey(plan, stageID)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	raw, err := ledger.store.Get(ctx, "stage-receipts", key)
	if err == nil && digest.SHA256(raw) == expectedDigest {
		return verifyLoadedStageReceipt(raw, expectedDigest, plan, stageID, predecessors)
	}
	if err != nil && !errors.Is(err, ErrRecordNotFound) {
		return stagereceipt.Verified{}, err
	}
	attemptKey, err := stageReceiptAttemptKey(plan, stageID, expectedDigest)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	raw, err = ledger.store.Get(ctx, "stage-receipts", attemptKey)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	return verifyLoadedStageReceipt(raw, expectedDigest, plan, stageID, predecessors)
}

func verifyLoadedStageReceipt(raw []byte, expectedDigest string, plan stageplan.Binding, stageID string, predecessors []stagereceipt.Verified) (stagereceipt.Verified, error) {
	verified, err := stagereceipt.Verify(raw, expectedDigest, plan, predecessors)
	if err != nil {
		return stagereceipt.Verified{}, fmt.Errorf("verify persisted stage receipt: %w", err)
	}
	receipt, err := verified.Receipt()
	if err != nil || receipt.StageID != stageID {
		return stagereceipt.Verified{}, errors.New("persisted stage receipt occupies a different stage")
	}
	return verified, nil
}

func stageReceiptKey(plan stageplan.Binding, stageID string) (string, error) {
	if _, _, err := plan.Stage(stageID); err != nil {
		return "", err
	}
	identity := struct {
		Format     string `json:"format"`
		PlanDigest string `json:"planDigest"`
		StageID    string `json:"stageId"`
	}{Format: stageReceiptSlotFormat, PlanDigest: plan.PlanDigest, StageID: stageID}
	_, identityDigest, err := canonicalRecord(identity)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(identityDigest, "sha256:"), nil
}

func stageReceiptAttemptKey(plan stageplan.Binding, stageID, receiptDigest string) (string, error) {
	if _, _, err := plan.Stage(stageID); err != nil {
		return "", err
	}
	if !validDigest(receiptDigest) {
		return "", errors.New("retry stage receipt digest is invalid")
	}
	identity := struct {
		Format        string `json:"format"`
		PlanDigest    string `json:"planDigest"`
		StageID       string `json:"stageId"`
		ReceiptDigest string `json:"receiptDigest"`
	}{Format: stageReceiptAttemptSlotFormat, PlanDigest: plan.PlanDigest, StageID: stageID, ReceiptDigest: receiptDigest}
	_, identityDigest, err := canonicalRecord(identity)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(identityDigest, "sha256:"), nil
}
