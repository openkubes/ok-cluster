package ledger

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyStageClaimRereadsExactDurableRecord(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	grant := verifiedStageGrant(t, at)
	claim, err := store.ClaimStage(context.Background(), grant, at)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := store.VerifyStageClaim(context.Background(), claim)
	if err != nil || !validDigest(digest) {
		t.Fatalf("exact durable stage claim was not verified: %s %v", digest, err)
	}
	if pendingDigest, err := store.VerifyPendingStageClaim(context.Background(), claim); err != nil || pendingDigest != digest {
		t.Fatalf("exact claim without terminal outcome was not pending: %s %v", pendingDigest, err)
	}
	changed := claim
	changed.Authority = "another-authority"
	if _, err := store.VerifyStageClaim(context.Background(), changed); err == nil {
		t.Fatal("a changed stage claim receipt matched the durable record")
	}
	missing := claim
	missing.GrantID = "ok147-stage-grant-20261020-99"
	if _, err := store.VerifyStageClaim(context.Background(), missing); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("missing durable claim did not fail as absent: %v", err)
	}
	if _, err := store.CompleteStage(context.Background(), claim, "STOPPED", "NOT_ATTEMPTED", stageSHA("e"), at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyPendingStageClaim(context.Background(), claim); err == nil {
		t.Fatal("claim with a durable terminal outcome was still accepted as pending")
	}
}
