package bootstrapauthority

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
	"github.com/openkubes/ok-cluster/internal/issuersourcecheck"
)

// This is a test-only rehearsal of the proposed source/coordination ordering,
// NOT a platform task or production integration. Authority itself does not load
// or validate a source/key. Repeated supplied snapshots do not establish live
// freshness, atomic source reads, authenticated plan provenance or store fencing.
// All keys, certificates, metadata and records below are generated in memory.
type sourceContractFixture struct {
	metadata, caDER, keyPEM []byte
	owner                   bootstrapcheck.SourceOwner
}

func newSourceContractFixture(t *testing.T, f fixture) sourceContractFixture {
	t.Helper()
	b := f.inputs.Expected
	owner := bootstrapcheck.SourceOwner{APIVersion: "cluster.x-k8s.io/v1beta1", Name: "fixture-cluster"}
	metadata, err := json.Marshal(map[string]any{
		"apiVersion": "meta.k8s.io/v1", "kind": "PartialObjectMetadata",
		"metadata": map[string]any{
			"name": b.SourceName, "namespace": b.SourceNamespace, "uid": b.SourceUID, "resourceVersion": b.SourceResourceVersion,
			"ownerReferences": []any{map[string]any{
				"apiVersion": owner.APIVersion, "kind": "Cluster", "name": owner.Name, "uid": b.SourceOwnerUID, "controller": true,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return sourceContractFixture{metadata, append([]byte(nil), f.inputs.CADER...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), owner}
}

// Only tests call this composition; there is no exported executable task seam.
// The inputs are synthetic expectations, not evidence of a real predecessor.
func verifySourceContractFixture(f fixture, source sourceContractFixture) (VerifiedRequest, error) {
	verified, err := f.a.Verify(f.r, f.inputs, f.now)
	if err != nil {
		return VerifiedRequest{}, err
	}
	if err := issuersourcecheck.Validate(source.metadata, source.caDER, source.keyPEM, f.inputs.Expected, source.owner); err != nil {
		return VerifiedRequest{}, err
	}
	return verified, nil
}

func assertSourceContractStore(t *testing.T, f fixture, claims, results int) {
	t.Helper()
	if f.store.claimWrites != claims || f.store.resultWrites != results {
		t.Fatalf("unexpected store writes: claims=%d results=%d", f.store.claimWrites, f.store.resultWrites)
	}
}

func TestOfflineSourceCoordinationRecordsBothObserverRoles(t *testing.T) {
	for _, role := range []string{"network-observer", "runtime-observer"} {
		t.Run(role, func(t *testing.T) {
			f := newFixture(t)
			if role == "runtime-observer" {
				f.inputs.Expected.Role, f.r.Request.Binding.Role = role, role
				f.inputs.PredecessorStage, f.r.PredecessorStage = 5, 5
				f.inputs.PredecessorReceiptDigest = digest([]byte("stage5"))
				f.r.PredecessorReceiptDigest = f.inputs.PredecessorReceiptDigest
				csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: "ok147:" + f.inputs.OperationNonce + ":" + role},
				}, f.leafKey)
				if err != nil {
					t.Fatal(err)
				}
				f.r.Request.CSRDER = csr
				f.signRequest(t)
			}
			source := newSourceContractFixture(t, f)
			verified, err := verifySourceContractFixture(f, source)
			if err != nil {
				t.Fatal(err)
			}
			assertSourceContractStore(t, f, 0, 0)
			claim, err := f.a.Claim(context.Background(), verified, f.now)
			if err != nil {
				t.Fatal(err)
			}
			// A future task must obtain fresh bound evidence here. Rechecking the
			// same in-memory bytes only rehearses validation, not API freshness.
			if err := issuersourcecheck.Validate(source.metadata, source.caDER, source.keyPEM, f.inputs.Expected, source.owner); err != nil {
				t.Fatal(err)
			}
			result := f.result(t, claim) // Synthetic signing fixture, not a task.
			if err := f.a.Complete(context.Background(), claim, result, f.now); err != nil {
				t.Fatal(err)
			}
			assertSourceContractStore(t, f, 1, 1)
			replacement, err := New(f.trust, f.store)
			if err != nil {
				t.Fatal(err)
			}
			state, err := replacement.Inspect(context.Background(), f.r, f.inputs)
			if err != nil || state.State != "RESULT_RECORDED_NOT_STAGE_AUTHORIZED" || state.Result == nil || !bytes.Equal(state.Result.Result.CertificateDER, result.Result.CertificateDER) {
				t.Fatalf("recorded result differs or became stage authorization: state=%s err=%v", state.State, err)
			}
			budget := bootstrapcheck.ObserverBudget{IssuedAt: result.IssuedAt, PollTimeout: f.r.PollTimeout, WrapperOverhead: f.r.WrapperOverhead}
			if err := bootstrapcheck.ValidateObserverStageEntry(f.r.Request, state.Result.Result, f.inputs, budget, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err := replacement.Claim(context.Background(), verified, f.now); !errors.Is(err, ErrConsumed) {
				t.Fatalf("successful source check reopened a consumed slot: %v", err)
			}
			// Public historical retrieval is not authority to reuse expired access.
			if _, err := replacement.Verify(f.r, f.inputs, f.now.Add(time.Hour)); err == nil {
				t.Fatal("recorded result made expired request active")
			}
		})
	}
}

func TestOfflineSourceCoordinationRejectsBeforeClaim(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *fixture, *sourceContractFixture){
		"signed target drift": func(t *testing.T, f *fixture, _ *sourceContractFixture) {
			f.r.Request.Binding.TargetUID, f.r.Request.Binding.SourceOwnerUID = "different-target", "different-target"
			f.signRequest(t)
		},
		"signed role drift": func(t *testing.T, f *fixture, _ *sourceContractFixture) {
			f.r.Request.Binding.Role = "runtime-observer"
			f.signRequest(t)
		},
		"signed predecessor drift": func(t *testing.T, f *fixture, _ *sourceContractFixture) {
			f.r.PredecessorReceiptDigest = digest([]byte("different-predecessor"))
			f.signRequest(t)
		},
		"expired request": func(t *testing.T, f *fixture, _ *sourceContractFixture) {
			f.r.NotAfter = f.now
			f.signRequest(t)
		},
		"invalid signature": func(_ *testing.T, f *fixture, _ *sourceContractFixture) { f.r.Signature[0] ^= 1 },
		"source UID": func(_ *testing.T, f *fixture, s *sourceContractFixture) {
			s.metadata = bytes.ReplaceAll(s.metadata, []byte(f.inputs.Expected.SourceUID), []byte("recreated-source"))
		},
		"source RV": func(_ *testing.T, _ *fixture, s *sourceContractFixture) {
			s.metadata = bytes.ReplaceAll(s.metadata, []byte(`"resourceVersion":"123"`), []byte(`"resourceVersion":"124"`))
		},
		"source owner": func(_ *testing.T, f *fixture, s *sourceContractFixture) {
			s.metadata = bytes.ReplaceAll(s.metadata, []byte(f.inputs.Expected.SourceOwnerUID), []byte("different-owner"))
		},
		"full Secret": func(_ *testing.T, _ *fixture, s *sourceContractFixture) {
			s.metadata = []byte(`{"apiVersion":"v1","kind":"Secret","data":{}}`)
		},
		"CA bytes": func(t *testing.T, _ *fixture, s *sourceContractFixture) { s.caDER = newFixture(t).inputs.CADER },
		"private key": func(t *testing.T, _ *fixture, s *sourceContractFixture) {
			s.keyPEM = newSourceContractFixture(t, newFixture(t)).keyPEM
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			source := newSourceContractFixture(t, f)
			mutate(t, &f, &source)
			verified, err := verifySourceContractFixture(f, source)
			if err == nil || verified.verified || strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatalf("invalid source/request produced verified composition or disclosed material: %v", err)
			}
			assertSourceContractStore(t, f, 0, 0)
		})
	}
}

func TestOfflineSourceDriftAfterClaimLeavesTerminalSlot(t *testing.T) {
	f := newFixture(t)
	source := newSourceContractFixture(t, f)
	verified, err := verifySourceContractFixture(f, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Claim(context.Background(), verified, f.now); err != nil {
		t.Fatal(err)
	}
	source.metadata = bytes.ReplaceAll(source.metadata, []byte(`"resourceVersion":"123"`), []byte(`"resourceVersion":"124"`))
	if issuersourcecheck.Validate(source.metadata, source.caDER, source.keyPEM, f.inputs.Expected, source.owner) == nil {
		t.Fatal("accepted changed source after claim")
	}
	assertSourceContractStore(t, f, 1, 0) // No synthetic signing or completion.
	replacement, err := New(f.trust, f.store)
	if err != nil {
		t.Fatal(err)
	}
	state, err := replacement.Inspect(context.Background(), f.r, f.inputs)
	if err != nil || state.State != "CLAIMED_INDETERMINATE_STOP" || state.Result != nil {
		t.Fatalf("source drift did not retain STOP: state=%s err=%v", state.State, err)
	}
	if _, err := replacement.Claim(context.Background(), verified, f.now); !errors.Is(err, ErrConsumed) {
		t.Fatalf("restarted authority reopened the slot: %v", err)
	}
	// Even a newly authenticated request bound to the changed source may not
	// reset the same plan/attempt/target/role slot or replace its original claim.
	f.inputs.Expected.SourceResourceVersion, f.r.Request.Binding.SourceResourceVersion = "124", "124"
	f.signRequest(t)
	updated, err := verifySourceContractFixture(f, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Claim(context.Background(), updated, f.now); !errors.Is(err, ErrStop) {
		t.Fatalf("source rebinding reset an indeterminate slot: %v", err)
	}
	assertSourceContractStore(t, f, 1, 0)
}

func TestOfflineSourceCoordinationUnknownResultDoesNotReissue(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "write did not commit"
		if committed {
			name = "write committed but response lost"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			source := newSourceContractFixture(t, f)
			verified, err := verifySourceContractFixture(f, source)
			if err != nil {
				t.Fatal(err)
			}
			claim, err := f.a.Claim(context.Background(), verified, f.now)
			if err != nil {
				t.Fatal(err)
			}
			result := f.result(t, claim)
			f.store.failResult, f.store.commitResult = true, committed
			if err := f.a.Complete(context.Background(), claim, result, f.now); !errors.Is(err, ErrStop) {
				t.Fatalf("unknown write became a successful handoff: %v", err)
			}
			replacement, err := New(f.trust, f.store)
			if err != nil {
				t.Fatal(err)
			}
			state, err := replacement.Inspect(context.Background(), f.r, f.inputs)
			wantState := "CLAIMED_INDETERMINATE_STOP"
			if committed {
				wantState = "RESULT_RECORDED_NOT_STAGE_AUTHORIZED"
			}
			if err != nil || state.State != wantState || (state.Result != nil) != committed {
				t.Fatalf("unknown result inspection differs: state=%s err=%v", state.State, err)
			}
			if _, err := replacement.Claim(context.Background(), verified, f.now); !errors.Is(err, ErrConsumed) {
				t.Fatalf("unknown write permitted another issuance: %v", err)
			}
			assertSourceContractStore(t, f, 1, 1)
		})
	}
}

func TestOfflineValidSourceDoesNotAuthorizeAnotherIssuerCertificate(t *testing.T) {
	f := newFixture(t)
	verified, err := verifySourceContractFixture(f, newSourceContractFixture(t, f))
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.a.Claim(context.Background(), verified, f.now)
	if err != nil {
		t.Fatal(err)
	}
	result := f.result(t, claim)
	template, err := x509.ParseCertificate(result.Result.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	other := newFixture(t)
	// Keep CSR key, subject, lifetime, request/claim binding and authenticated
	// result signer correct. Only the leaf's CA signature is different.
	result.Result.CertificateDER, err = x509.CreateCertificate(rand.Reader, template, other.ca, f.leafKey.Public(), other.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.signResult(t, &result)
	entryErr := bootstrapcheck.ValidateObserverStageEntry(f.r.Request, result.Result, f.inputs, bootstrapcheck.ObserverBudget{
		IssuedAt: result.IssuedAt, PollTimeout: f.r.PollTimeout, WrapperOverhead: f.r.WrapperOverhead,
	}, f.now)
	if entryErr == nil || entryErr.Error() != "bootstrap certificate issuer rejected" {
		t.Fatalf("wrong-CA fixture did not reach the issuer check: %v", entryErr)
	}
	if err := f.a.Complete(context.Background(), claim, result, f.now); !errors.Is(err, ErrStop) {
		t.Fatalf("valid source/authenticated result bypassed certificate issuer binding: %v", err)
	}
	assertSourceContractStore(t, f, 1, 0)
}
