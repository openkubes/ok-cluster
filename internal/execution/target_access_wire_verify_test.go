package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/ledger"
)

func TestVerifyTargetAccessDispatchWireRequiresIndependentExactBindings(t *testing.T) {
	dispatch := validTargetAccessDispatchForWireTest(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	predecessors := []authorization.StagePredecessor{{StageID: "runtime-binding", OutcomeDigest: stagedSHA("6")}}
	predecessorDigest, err := canonicalDigest(predecessors)
	if err != nil {
		t.Fatal(err)
	}
	request := dispatch.Mutation
	request.PredecessorDigest = predecessorDigest
	request.StageClaim.PredecessorDigest = predecessorDigest
	request.StageClaim.ClaimedAt = at.Format(time.RFC3339Nano)
	dispatch.Mutation = request
	payload := authorization.StagePayload{
		Audience: authorization.StageAudience, GrantID: request.GrantID, Decision: "ALLOW",
		PlanDigest: request.PlanDigest, ContractIdentity: request.ContractIdentity,
		ContractRevision: request.ContractRevision, EnablementRevision: request.EnablementRevision,
		PlatformRevision: request.PlatformRevision, ExecutionFixture: request.ExecutionFixture,
		ExecutionAttempt: request.ExecutionAttemptDigest, StageID: request.StageID, StageOrder: request.StageOrder,
		StageDigest: request.StageDigest, Operation: request.Operation, Authority: request.Authority,
		Predecessors: predecessors, NotBefore: at.Add(-time.Minute).Format(time.RFC3339),
		NotAfter: at.Add(10 * time.Minute).Format(time.RFC3339), MaxUses: 1,
	}
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		t.Fatal(err)
	}
	keyID := digest.SHA256(publicKey)
	grantRaw, err := json.Marshal(struct {
		Format    string                     `json:"format"`
		Payload   authorization.StagePayload `json:"payload"`
		Signature struct {
			Algorithm string `json:"algorithm"`
			KeyID     string `json:"keyId"`
			Value     string `json:"value"`
		} `json:"signature"`
	}{Format: authorization.StageFormat, Payload: payload, Signature: struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"keyId"`
		Value     string `json:"value"`
	}{Algorithm: "Ed25519", KeyID: keyID, Value: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))}})
	if err != nil {
		t.Fatal(err)
	}
	dispatch.Mutation.AuthorizationEnvelope = grantRaw
	dispatch.Mutation.AuthorizationDigest = digest.SHA256(grantRaw)
	dispatch.Mutation.AuthorizationKeyID = keyID
	dispatch.Mutation.StageClaim.AuthorizationDigest = dispatch.Mutation.AuthorizationDigest
	dispatch.Mutation.StageClaim.KeyID = keyID
	dispatch.DispatchID, err = targetAccessDispatchID(dispatch.Mutation, dispatch.ArtifactDigest, dispatch.TargetIdentityDigest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeTargetAccessDispatch(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	objects := make([]TargetAccessWireObjectExpectation, len(dispatch.Plane.Objects))
	for i, object := range dispatch.Plane.Objects {
		objects[i] = TargetAccessWireObjectExpectation{Identity: object.Identity, Digest: object.Digest, CollectionPath: object.CollectionPath, ObjectPath: object.ObjectPath}
	}
	expected := TargetAccessWireExpectation{
		TrustedPublicKey: []byte(base64.StdEncoding.EncodeToString(publicKey)), ArtifactDigest: dispatch.ArtifactDigest,
		TargetIdentityDigest: dispatch.TargetIdentityDigest, Objects: objects,
		Authorization: authorization.StageDispatchExpectation{
			AuthorizationDigest: dispatch.Mutation.AuthorizationDigest, AuthorizationKeyID: keyID,
			GrantID: payload.GrantID, PlanDigest: payload.PlanDigest, ContractIdentity: payload.ContractIdentity,
			ContractRevision: payload.ContractRevision, EnablementRevision: payload.EnablementRevision,
			PlatformRevision: payload.PlatformRevision, ExecutionFixture: payload.ExecutionFixture,
			ExecutionAttempt: payload.ExecutionAttempt, StageID: payload.StageID, StageOrder: payload.StageOrder,
			StageDigest: payload.StageDigest, Operation: payload.Operation, Authority: payload.Authority,
			PredecessorDigest: predecessorDigest, RequiredPredecessors: []string{"runtime-binding"},
		},
	}
	verified, err := VerifyTargetAccessDispatchWire(wire, expected, at)
	if err != nil {
		t.Fatalf("exact receiver-bound grant was rejected: %v", err)
	}
	if verified.Mutation.verifiedStageGrant || len(verified.Plane.Objects) != len(objects) {
		t.Fatal("offline receiver verification incorrectly recreated local claim authority")
	}
	ledgerRoot := t.TempDir()
	if err := os.Chmod(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	stageLedger, err := ledger.Open(ledgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyTargetAccessDispatchWithLedger(context.Background(), wire, expected, at, stageLedger); err == nil {
		t.Fatal("receiver accepted a signed dispatch whose stage claim is absent from its durable ledger")
	}

	wrong := expected
	wrong.ArtifactDigest = stagedSHA("1")
	if _, err := VerifyTargetAccessDispatchWire(wire, wrong, at); err == nil {
		t.Fatal("dispatch with a different independently expected artifact was accepted")
	}
	wrong = expected
	wrong.Objects = append([]TargetAccessWireObjectExpectation(nil), expected.Objects...)
	wrong.Objects[0].Digest = stagedSHA("1")
	if _, err := VerifyTargetAccessDispatchWire(wire, wrong, at); err == nil {
		t.Fatal("dispatch with a different independently expected object digest was accepted")
	}
	if _, err := VerifyTargetAccessDispatchWire(wire, expected, at.Add(11*time.Minute)); err == nil {
		t.Fatal("expired signed grant was accepted by the receiver verifier")
	}
}
