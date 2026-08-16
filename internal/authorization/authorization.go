// Package authorization verifies a content-bound, signed, single-use decision.
// It does not issue grants or decide policy.
package authorization

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	Format        = "ok147-create-authorization/v1"
	Audience      = "ok-cluster-contract-executor"
	MaximumWindow = 30 * time.Minute
)

// Payload is the exact decision signed by an external authority.
type Payload struct {
	Audience                 string            `json:"audience"`
	GrantID                  string            `json:"grantId"`
	Decision                 string            `json:"decision"`
	Operation                string            `json:"operation"`
	RequestDigest            string            `json:"requestDigest"`
	ContractIdentity         contract.Identity `json:"contractIdentity"`
	ContractRevision         string            `json:"contractRevision"`
	ProjectionManifestDigest string            `json:"projectionManifestDigest"`
	NotBefore                string            `json:"notBefore"`
	NotAfter                 string            `json:"notAfter"`
	MaxUses                  int               `json:"maxUses"`
}

type signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

type envelope struct {
	Format    string    `json:"format"`
	Payload   Payload   `json:"payload"`
	Signature signature `json:"signature"`
}

// Receipt records what was cryptographically checked. It is not evidence that
// the grant has been consumed; single-use enforcement belongs to submission.
type Receipt struct {
	Format              string `json:"format"`
	State               string `json:"state"`
	AuthorizationDigest string `json:"authorizationDigest"`
	GrantID             string `json:"grantId"`
	KeyID               string `json:"keyId"`
	NotAfter            string `json:"notAfter"`
	MaxUses             int    `json:"maxUses"`
}

// ConsumptionBinding is the minimum verified identity required by the local
// single-use ledger. It contains no signature, key material, or source path.
type ConsumptionBinding struct {
	AuthorizationDigest      string
	GrantID                  string
	KeyID                    string
	Operation                string
	RequestDigest            string
	ContractRevision         string
	ProjectionManifestDigest string
	NotAfter                 string
}

// VerifiedGrant can only be produced by Verify. The unexported marker prevents
// callers from manufacturing a grant by constructing a Receipt value.
type VerifiedGrant struct {
	receipt  Receipt
	binding  ConsumptionBinding
	verified bool
}

// Receipt returns the redacted verification result for plan output.
func (grant VerifiedGrant) Receipt() Receipt { return grant.receipt }

// ConsumptionBinding returns verified fields for a single-use claim.
func (grant VerifiedGrant) ConsumptionBinding() (ConsumptionBinding, error) {
	if !grant.verified {
		return ConsumptionBinding{}, errors.New("authorization grant was not produced by verification")
	}
	return grant.binding, nil
}

// Verify checks the signature, trust key identity, time window, single-use
// declaration, and every request binding.
func Verify(raw, publicKeyRaw []byte, request executor.CreateRequest, at time.Time) (VerifiedGrant, error) {
	var document envelope
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return VerifiedGrant{}, fmt.Errorf("decode authorization: %w", err)
	}
	if document.Format != Format {
		return VerifiedGrant{}, fmt.Errorf("authorization format %q is not supported", document.Format)
	}
	publicKey, keyID, err := parsePublicKey(publicKeyRaw)
	if err != nil {
		return VerifiedGrant{}, err
	}
	if document.Signature.Algorithm != "Ed25519" {
		return VerifiedGrant{}, fmt.Errorf("signature algorithm %q is not supported", document.Signature.Algorithm)
	}
	if document.Signature.KeyID != keyID {
		return VerifiedGrant{}, fmt.Errorf("authorization keyId %s does not match trusted key %s", document.Signature.KeyID, keyID)
	}
	signatureBytes, err := base64.StdEncoding.Strict().DecodeString(document.Signature.Value)
	if err != nil {
		return VerifiedGrant{}, fmt.Errorf("decode authorization signature: %w", err)
	}
	signed, err := SigningBytes(document.Payload)
	if err != nil {
		return VerifiedGrant{}, err
	}
	if !ed25519.Verify(publicKey, signed, signatureBytes) {
		return VerifiedGrant{}, errors.New("authorization signature verification failed")
	}
	if err := verifyPayload(document.Payload, request, at); err != nil {
		return VerifiedGrant{}, err
	}
	receipt := Receipt{
		Format:              "ok147-authorization-receipt/v1",
		State:               "VERIFIED",
		AuthorizationDigest: digest.SHA256(raw),
		GrantID:             document.Payload.GrantID,
		KeyID:               keyID,
		NotAfter:            document.Payload.NotAfter,
		MaxUses:             document.Payload.MaxUses,
	}
	return VerifiedGrant{
		receipt: receipt,
		binding: ConsumptionBinding{
			AuthorizationDigest:      receipt.AuthorizationDigest,
			GrantID:                  document.Payload.GrantID,
			KeyID:                    keyID,
			Operation:                document.Payload.Operation,
			RequestDigest:            document.Payload.RequestDigest,
			ContractRevision:         document.Payload.ContractRevision,
			ProjectionManifestDigest: document.Payload.ProjectionManifestDigest,
			NotAfter:                 document.Payload.NotAfter,
		},
		verified: true,
	}, nil
}

// SigningBytes returns the canonical bytes an authority signs.
func SigningBytes(payload Payload) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

func verifyPayload(payload Payload, request executor.CreateRequest, at time.Time) error {
	if payload.Audience != Audience {
		return fmt.Errorf("authorization audience %q is not accepted", payload.Audience)
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,127}$`).MatchString(payload.GrantID) {
		return errors.New("authorization grantId is invalid")
	}
	if payload.Decision != "ALLOW" {
		return fmt.Errorf("authorization decision is %q, not ALLOW", payload.Decision)
	}
	if payload.Operation != request.Operation {
		return errors.New("authorization operation differs from request")
	}
	requestDigest, err := executor.Digest(request)
	if err != nil {
		return err
	}
	if payload.RequestDigest != requestDigest {
		return errors.New("authorization request digest differs from request")
	}
	if payload.ContractIdentity != request.ContractIdentity {
		return errors.New("authorization contract identity differs from request")
	}
	if payload.ContractRevision != request.ContractRevision {
		return errors.New("authorization contract revision differs from request")
	}
	if payload.ProjectionManifestDigest != request.Projection.ManifestDigest {
		return errors.New("authorization projection manifest digest differs from request")
	}
	if payload.MaxUses != 1 {
		return errors.New("authorization must declare exactly one use")
	}
	notBefore, err := time.Parse(time.RFC3339, payload.NotBefore)
	if err != nil {
		return fmt.Errorf("authorization notBefore: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, payload.NotAfter)
	if err != nil {
		return fmt.Errorf("authorization notAfter: %w", err)
	}
	if !notAfter.After(notBefore) {
		return errors.New("authorization time window is empty")
	}
	if notAfter.Sub(notBefore) > MaximumWindow {
		return fmt.Errorf("authorization time window exceeds %s", MaximumWindow)
	}
	if at.Before(notBefore) || !at.Before(notAfter) {
		return errors.New("authorization is not active at the evaluation time")
	}
	return nil
}

func parsePublicKey(raw []byte) (ed25519.PublicKey, string, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("decode trusted Ed25519 public key: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("trusted Ed25519 public key has %d bytes, expected %d", len(decoded), ed25519.PublicKeySize)
	}
	publicKey := ed25519.PublicKey(decoded)
	return publicKey, digest.SHA256(decoded), nil
}
