package authorization

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// StageDispatchExpectation is trusted receiver configuration plus the exact
// operation envelope it intends to accept. RequiredPredecessors is an ordered,
// receiver-owned list; predecessor receipt digests remain covered by the grant.
type StageDispatchExpectation struct {
	AuthorizationDigest  string
	AuthorizationKeyID   string
	GrantID              string
	PlanDigest           string
	ContractIdentity     contract.Identity
	ContractRevision     string
	EnablementRevision   string
	PlatformRevision     string
	ExecutionFixture     string
	ExecutionAttempt     string
	StageID              string
	StageOrder           int
	StageDigest          string
	Operation            string
	Authority            string
	PredecessorDigest    string
	RequiredPredecessors []string
}

// VerifyStageDispatchAuthorization verifies a public signed stage grant for a
// delegated receiver. trustedPublicKey is independently configured by that
// receiver, not supplied by the request. The check performs no persistence or
// operation; a separate durable one-shot fence is still required.
func VerifyStageDispatchAuthorization(raw, trustedPublicKey []byte, expected StageDispatchExpectation, at time.Time) error {
	publicKey, keyID, err := parsePublicKey(trustedPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || at.IsZero() || !validDispatchExpectation(expected, keyID) || len(raw) == 0 || len(raw) > maximumStageGrantBytes || digest.SHA256(raw) != expected.AuthorizationDigest {
		return errors.New("stage dispatch authorization is not accepted")
	}
	var envelope stageEnvelope
	if jsonstrict.Decode(raw, &envelope) != nil || (envelope.Format != StageFormat && envelope.Format != StageFormatV2) || envelope.Signature.Algorithm != "Ed25519" || envelope.Signature.KeyID != keyID || envelope.Signature.KeyID != expected.AuthorizationKeyID {
		return errors.New("stage dispatch authorization is not accepted")
	}
	signatureBytes, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature.Value)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize {
		return errors.New("stage dispatch authorization is not accepted")
	}
	signed, err := StageSigningBytes(envelope.Payload)
	if err != nil || !ed25519.Verify(publicKey, signed, signatureBytes) {
		return errors.New("stage dispatch authorization is not accepted")
	}
	payload := envelope.Payload
	if payload.Audience != StageAudience || payload.Decision != "ALLOW" || payload.MaxUses != 1 ||
		payload.GrantID != expected.GrantID || payload.PlanDigest != expected.PlanDigest || payload.ContractIdentity != expected.ContractIdentity ||
		payload.ContractRevision != expected.ContractRevision || payload.EnablementRevision != expected.EnablementRevision ||
		payload.PlatformRevision != expected.PlatformRevision || payload.ExecutionFixture != expected.ExecutionFixture ||
		payload.ExecutionAttempt != expected.ExecutionAttempt || payload.StageID != expected.StageID || payload.StageOrder != expected.StageOrder ||
		payload.StageDigest != expected.StageDigest || payload.Operation != expected.Operation || payload.Authority != expected.Authority {
		return errors.New("stage dispatch authorization is not accepted")
	}
	notBefore, errBefore := time.Parse(time.RFC3339, payload.NotBefore)
	notAfter, errAfter := time.Parse(time.RFC3339, payload.NotAfter)
	if errBefore != nil || errAfter != nil || !notAfter.After(notBefore) || notAfter.Sub(notBefore) > MaximumWindow || at.Before(notBefore) || !at.Before(notAfter) {
		return errors.New("stage dispatch authorization is not accepted")
	}
	predecessorDigest, err := dispatchPredecessorDigest(payload.Predecessors, expected.RequiredPredecessors)
	if err != nil || predecessorDigest != expected.PredecessorDigest {
		return errors.New("stage dispatch authorization is not accepted")
	}
	return nil
}

func validDispatchExpectation(expected StageDispatchExpectation, trustedKeyID string) bool {
	for _, value := range []string{expected.AuthorizationDigest, expected.AuthorizationKeyID, expected.PlanDigest, expected.StageDigest, expected.PredecessorDigest} {
		if !stageDigestPattern.MatchString(value) {
			return false
		}
	}
	return expected.AuthorizationKeyID == trustedKeyID && stageGrantIDPattern.MatchString(expected.GrantID) &&
		expected.ContractIdentity.Namespace != "" && expected.ContractIdentity.Name != "" && expected.ContractRevision != "" &&
		expected.EnablementRevision != "" && expected.PlatformRevision != "" && expected.ExecutionFixture != "" &&
		expected.StageID != "" && expected.StageOrder > 0 && expected.Operation != "" && expected.Authority != "" &&
		expected.RequiredPredecessors != nil
}

func dispatchPredecessorDigest(actual []StagePredecessor, requiredIDs []string) (string, error) {
	if actual == nil || requiredIDs == nil || len(actual) != len(requiredIDs) {
		return "", errors.New("dispatch predecessor set is incomplete")
	}
	for index, predecessor := range actual {
		if predecessor.StageID != requiredIDs[index] || !stageDigestPattern.MatchString(predecessor.OutcomeDigest) {
			return "", errors.New("dispatch predecessor set differs")
		}
	}
	raw, err := json.Marshal(actual)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}
