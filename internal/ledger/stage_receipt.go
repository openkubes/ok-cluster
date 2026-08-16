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

const stageReceiptSlotFormat = "ok147-stage-receipt-slot/v1"

var ErrStageReceiptConflict = errors.New("a different stage receipt already occupies the immutable slot")

// StoreStageReceipt persists one verified receipt in the deterministic slot
// for its plan and stage. An exact replay is idempotent; different content for
// the same slot fails closed.
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
	if !bytes.Equal(existing, raw) {
		return "", ErrStageReceiptConflict
	}
	if _, err := stagereceipt.Verify(existing, receiptDigest, plan, predecessors); err != nil {
		return "", fmt.Errorf("verify existing stage receipt: %w", err)
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

// LoadStageReceipt reads one deterministic slot and requires the receipt
// identity to be supplied independently by the caller.
func (ledger *Ledger) LoadStageReceipt(ctx context.Context, plan stageplan.Binding, stageID, expectedDigest string, predecessors []stagereceipt.Verified) (stagereceipt.Verified, error) {
	key, err := stageReceiptKey(plan, stageID)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	raw, err := ledger.store.Get(ctx, "stage-receipts", key)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
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
