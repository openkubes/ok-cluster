package authorization

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/projection"
)

func TestVerifyAcceptsExactSignedRequest(t *testing.T) {
	request := testRequest()
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	raw, publicPEM := signAuthorization(t, request, at)
	grant, err := Verify(raw, publicPEM, request, at)
	if err != nil {
		t.Fatal(err)
	}
	receipt := grant.Receipt()
	if receipt.State != "VERIFIED" || receipt.GrantID != "ok147-create-20260816-01" || receipt.MaxUses != 1 {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if receipt.AuthorizationDigest != digest.SHA256(raw) {
		t.Fatal("authorization digest differs from raw document")
	}
	binding, err := grant.ConsumptionBinding()
	if err != nil || binding.RequestDigest == "" || binding.Operation != "CreateCluster" {
		t.Fatalf("invalid consumption binding: %#v %v", binding, err)
	}
}

func TestZeroGrantCannotProduceConsumptionBinding(t *testing.T) {
	if _, err := (VerifiedGrant{}).ConsumptionBinding(); err == nil {
		t.Fatal("zero grant was accepted")
	}
}

func TestVerifyFailsClosed(t *testing.T) {
	request := testRequest()
	at := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	raw, publicPEM := signAuthorization(t, request, at)

	t.Run("changed request", func(t *testing.T) {
		changed := request
		changed.Projection.ManifestDigest = "sha256:" + strings.Repeat("9", 64)
		if _, err := Verify(raw, publicPEM, changed, at); err == nil || !strings.Contains(err.Error(), "request digest") {
			t.Fatalf("expected request mismatch, got %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := Verify(raw, publicPEM, request, at.Add(31*time.Minute)); err == nil || !strings.Contains(err.Error(), "not active") {
			t.Fatalf("expected expiry rejection, got %v", err)
		}
	})
	t.Run("wrong trust key", func(t *testing.T) {
		otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		other := []byte(base64.StdEncoding.EncodeToString(otherPublic))
		if _, err := Verify(raw, other, request, at); err == nil || !strings.Contains(err.Error(), "keyId") {
			t.Fatalf("expected trust-key rejection, got %v", err)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		var document envelope
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		document.Payload.Decision = "DENY"
		tampered, _ := json.Marshal(document)
		if _, err := Verify(tampered, publicPEM, request, at); err == nil || !strings.Contains(err.Error(), "signature verification") {
			t.Fatalf("expected signature rejection, got %v", err)
		}
	})
}

func testRequest() executor.CreateRequest {
	identity := contract.Identity{Name: "disposable-ok141", Namespace: "disposable-ok141"}
	return executor.CreateRequest{
		Format:                  executor.RequestFormat,
		Operation:               "CreateCluster",
		ContractIdentity:        identity,
		ContractRevision:        "sha256:" + strings.Repeat("1", 64),
		CanonicalizationProfile: contract.CanonicalizationProfile,
		RawArtifactDigest:       "sha256:" + strings.Repeat("2", 64),
		SchemaDigest:            "sha256:" + strings.Repeat("3", 64),
		Projection: projection.Binding{
			Format:              projection.BindingFormat,
			SourceFormat:        "ok141-contract-to-capi-projection/v2",
			ManifestDigest:      "sha256:" + strings.Repeat("4", 64),
			AuthorityMapDigest:  "sha256:" + strings.Repeat("5", 64),
			IntentRevision:      "sha256:" + strings.Repeat("1", 64),
			ContractIdentity:    identity,
			InfrastructurePlane: projection.Plane{Identity: "ok-infra", Role: "provider-runtime-and-golden-image-prerequisites", ResourceCount: 3},
			ManagementPlane:     projection.Plane{Identity: "ok-mgmt", Role: "single-lifecycle-writer", ResourceCount: 8},
			Artifacts:           []projection.Artifact{{Name: "authority-map.json", Digest: "sha256:" + strings.Repeat("5", 64)}},
		},
	}
}

func signAuthorization(t *testing.T, request executor.CreateRequest, at time.Time) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := executor.Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	payload := Payload{
		Audience:                 Audience,
		GrantID:                  "ok147-create-20260816-01",
		Decision:                 "ALLOW",
		Operation:                request.Operation,
		RequestDigest:            requestDigest,
		ContractIdentity:         request.ContractIdentity,
		ContractRevision:         request.ContractRevision,
		ProjectionManifestDigest: request.Projection.ManifestDigest,
		NotBefore:                at.Add(-time.Minute).Format(time.RFC3339),
		NotAfter:                 at.Add(29 * time.Minute).Format(time.RFC3339),
		MaxUses:                  1,
	}
	signed, err := SigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	document := envelope{
		Format:  Format,
		Payload: payload,
		Signature: signature{
			Algorithm: "Ed25519",
			KeyID:     digest.SHA256(publicKey),
			Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed)),
		},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw, []byte(base64.StdEncoding.EncodeToString(publicKey) + "\n")
}
