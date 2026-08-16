package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/projection"
)

func TestClaimIsAtomicAndSingleUse(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := verifiedGrant(t, at)
	available, err := store.Inspect(grant)
	if err != nil || available.State != "AVAILABLE" || !available.ClaimAllowed {
		t.Fatalf("grant is not initially available: %#v %v", available, err)
	}

	var acquired atomic.Int32
	var consumed atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 24; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := store.Claim(grant, at); err == nil {
				acquired.Add(1)
			} else if errors.Is(err, ErrGrantConsumed) {
				consumed.Add(1)
			} else {
				t.Errorf("claim: %v", err)
			}
		}()
	}
	wait.Wait()
	if acquired.Load() != 1 || consumed.Load() != 23 {
		t.Fatalf("acquired=%d consumed=%d", acquired.Load(), consumed.Load())
	}
	inspection, err := store.Inspect(grant)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.State != "CLAIMED_INDETERMINATE_STOP" || inspection.ClaimAllowed {
		t.Fatalf("unsafe restart decision: %#v", inspection)
	}
}

func TestCompleteIsImmutableAndIdempotent(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := verifiedGrant(t, at)
	claim, err := store.Claim(grant, at)
	if err != nil {
		t.Fatal(err)
	}
	evidence := "sha256:" + strings.Repeat("e", 64)
	if _, err := store.Complete(claim, "SUCCEEDED", "NOT_ATTEMPTED", evidence, at.Add(time.Second)); err == nil {
		t.Fatal("successful CreateCluster without attempted mutation was accepted")
	}
	first, err := store.Complete(claim, "SUCCEEDED", "ATTEMPTED", evidence, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Complete(claim, "SUCCEEDED", "ATTEMPTED", evidence, at.Add(time.Second))
	if err != nil || second != first {
		t.Fatalf("identical completion was not idempotent: %#v %v", second, err)
	}
	if _, err := store.Complete(claim, "FAILED", "UNKNOWN", evidence, at.Add(2*time.Second)); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("expected conflicting completion rejection, got %v", err)
	}
	inspection, err := store.Inspect(grant)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.State != "COMPLETED" || inspection.ClaimAllowed || inspection.Outcome == nil || inspection.Outcome.Outcome != "SUCCEEDED" {
		t.Fatalf("unexpected completion inspection: %#v", inspection)
	}
}

func TestTamperedClaimFailsClosed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	grant := verifiedGrant(t, at)
	claim, err := store.Claim(grant, at)
	if err != nil {
		t.Fatal(err)
	}
	path := store.claimPath(claim.GrantID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(" "), raw...)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inspect(grant); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}

func TestOpenRejectsBroadDirectoryPermissions(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("expected permission rejection, got %v", err)
	}
}

func verifiedGrant(t *testing.T, at time.Time) authorization.VerifiedGrant {
	t.Helper()
	identity := contract.Identity{Name: "disposable-ok141", Namespace: "disposable-ok141"}
	request := executor.CreateRequest{
		Format: executor.RequestFormat, Operation: "CreateCluster", ContractIdentity: identity,
		ContractRevision: "sha256:" + strings.Repeat("1", 64),
		Projection: projection.Binding{
			Format: projection.BindingFormat, IntentRevision: "sha256:" + strings.Repeat("1", 64), ContractIdentity: identity,
			ManifestDigest: "sha256:" + strings.Repeat("2", 64),
		},
	}
	requestDigest, err := executor.Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := authorization.Payload{
		Audience: authorization.Audience, GrantID: "ok147-create-20260816-01", Decision: "ALLOW", Operation: request.Operation,
		RequestDigest: requestDigest, ContractIdentity: identity, ContractRevision: request.ContractRevision,
		ProjectionManifestDigest: request.Projection.ManifestDigest,
		NotBefore:                at.Add(-time.Minute).Format(time.RFC3339), NotAfter: at.Add(20 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	signed, err := authorization.SigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"format":  authorization.Format,
		"payload": payload,
		"signature": map[string]any{
			"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed)),
		},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authorization.Verify(raw, []byte(base64.StdEncoding.EncodeToString(publicKey)), request, at)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}
