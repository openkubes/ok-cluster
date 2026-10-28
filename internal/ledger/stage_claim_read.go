package ledger

import (
	"bytes"
	"context"
	"errors"
)

// VerifyStageClaim rereads one previously claimed stage grant by exact grant
// identity and compares it to the supplied receipt. Delegated executors can
// use this read-only check before dispatch; the receipt included in a request
// alone is not proof that the claim exists in the durable ledger.
func (ledger *Ledger) VerifyStageClaim(ctx context.Context, expected StageClaimReceipt) (string, error) {
	if ledger == nil || ledger.store == nil || expected.GrantID == "" {
		return "", errors.New("stage claim grant identity is required")
	}
	stored, identity, err := ledger.readStageClaim(ctx, expected.GrantID)
	if err != nil {
		return "", err
	}
	provided, _, providedErr := canonicalRecord(expected)
	canonicalStored, _, storedErr := canonicalRecord(stored)
	if providedErr != nil || storedErr != nil || !bytes.Equal(provided, canonicalStored) {
		return "", errors.New("provided stage claim differs from immutable ledger claim")
	}
	return identity, nil
}

// VerifyPendingStageClaim confirms that the exact claim exists and has no
// durable terminal outcome yet. This is a read-only replay check, not an
// atomic dispatch fence: a receiver must still create its own one-shot fence
// before handing work to a mutating executor.
func (ledger *Ledger) VerifyPendingStageClaim(ctx context.Context, expected StageClaimReceipt) (string, error) {
	identity, err := ledger.VerifyStageClaim(ctx, expected)
	if err != nil {
		return "", err
	}
	if _, _, err := ledger.readStageOutcome(ctx, expected.GrantID); err == nil {
		return "", errors.New("stage claim already has a durable terminal outcome")
	} else if !errors.Is(err, ErrRecordNotFound) {
		return "", err
	}
	return identity, nil
}
