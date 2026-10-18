// Package bootstrapauthority is an experimental candidate issuer authorization and
// coordination boundary. It has no signer, key loader or CLI/runner integration.
// The explicitly configured Kubernetes store is not installed or activated by
// this package; production storage properties are a separate trust boundary.
package bootstrapauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

const RequestAudience = "ok147-bootstrap-issuer-candidate"
const ResultAudience = "ok147-bootstrap-result-candidate"

// Trust is explicit platform input. No key file, default lifetime, trust-on-first
// use, stage-authority key reuse or independent-evidence key reuse is supported.
type Trust struct {
	RequestPublicKey                                           ed25519.PublicKey
	ResultPublicKey                                            ed25519.PublicKey
	StageKeyID, EvidenceKeyID, PolicyDigest, StoreDomainDigest string
	MaxRequestLifetime                                         time.Duration
}

// SignedRequest is an internal model, not an accepted public wire format.
type SignedRequest struct {
	Audience, KeyID, StoreDomainDigest string
	Request                            bootstrapcheck.Request
	OperationNonce                     string
	PredecessorStage                   int
	PredecessorReceiptDigest           string
	NotBefore, NotAfter                time.Time
	PollTimeout, WrapperOverhead       time.Duration
	Signature                          []byte
}

type VerifiedRequest struct {
	request                                      SignedRequest
	inputs                                       bootstrapcheck.ObserverInputs
	authorityID, authorizationDigest, slotDigest string
	verified                                     bool
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

// RequestSigningBytes constructs a domain-separated candidate message only. No
// production method accepts a private key or performs signing.
func RequestSigningBytes(r SignedRequest) ([]byte, error) {
	requestDigest, err := bootstrapcheck.RequestDigest(r.Request)
	if err != nil {
		return nil, errors.New("invalid issuer request binding")
	}
	return json.Marshal(struct {
		Domain, Audience, KeyID, StoreDomainDigest, RequestDigest, OperationNonce string
		PredecessorStage                                                          int
		PredecessorReceiptDigest, NotBefore, NotAfter                             string
		PollTimeout, WrapperOverhead                                              int64
	}{"ok147-bootstrap-request-signature-candidate/v1", r.Audience, r.KeyID, r.StoreDomainDigest, requestDigest, r.OperationNonce, r.PredecessorStage, r.PredecessorReceiptDigest, r.NotBefore.UTC().Format(time.RFC3339Nano), r.NotAfter.UTC().Format(time.RFC3339Nano), int64(r.PollTimeout), int64(r.WrapperOverhead)})
}

func (a *Authority) verify(r SignedRequest, inputs bootstrapcheck.ObserverInputs, now *time.Time) (VerifiedRequest, error) {
	var empty VerifiedRequest
	if r.Audience != RequestAudience || r.KeyID != digest(a.trust.RequestPublicKey) || r.StoreDomainDigest != a.trust.StoreDomainDigest || r.Request.Binding.PolicyDigest != a.trust.PolicyDigest || r.NotBefore.IsZero() || !r.NotAfter.After(r.NotBefore) || r.NotAfter.Sub(r.NotBefore) > a.trust.MaxRequestLifetime {
		return empty, errors.New("issuer request audience, key, policy or window rejected")
	}
	if now != nil && (now.IsZero() || now.Before(r.NotBefore) || !now.Before(r.NotAfter)) {
		return empty, errors.New("issuer request is not active")
	}
	if r.OperationNonce != inputs.OperationNonce || r.PredecessorStage != inputs.PredecessorStage || r.PredecessorReceiptDigest != inputs.PredecessorReceiptDigest || bootstrapcheck.ValidateObserverRequest(r.Request, inputs) != nil || bootstrapcheck.ValidateObserverPollingBudget(r.PollTimeout, r.WrapperOverhead) != nil {
		return empty, errors.New("issuer request differs from independent observer evidence")
	}
	ca, err := x509.ParseCertificate(inputs.CADER)
	if err != nil {
		return empty, errors.New("invalid issuer trust anchor")
	}
	if public, ok := ca.PublicKey.(ed25519.PublicKey); ok && (bytes.Equal(public, a.trust.RequestPublicKey) || bytes.Equal(public, a.trust.ResultPublicKey)) {
		return empty, errors.New("workload CA cannot authenticate issuer requests or results")
	}
	message, err := RequestSigningBytes(r)
	if err != nil || !ed25519.Verify(a.trust.RequestPublicKey, message, r.Signature) {
		return empty, errors.New("issuer request signature rejected")
	}
	slot, err := bootstrapcheck.SlotDigest(r.Request.Binding)
	if err != nil {
		return empty, errors.New("issuer slot rejected")
	}
	// Freeze all mutable byte slices after verification.
	r.Request.CSRDER = append([]byte(nil), r.Request.CSRDER...)
	r.Signature = append([]byte(nil), r.Signature...)
	inputs.CADER = append([]byte(nil), inputs.CADER...)
	return VerifiedRequest{r, inputs, a.id, digest(append(message, r.Signature...)), slot, true}, nil
}

// Verify authenticates this candidate request against independent platform
// expectations. It does not verify the authoritative predecessor receipts or
// live CA/RBAC itself; those expectations must already have been established.
func (a *Authority) Verify(r SignedRequest, inputs bootstrapcheck.ObserverInputs, now time.Time) (VerifiedRequest, error) {
	return a.verify(r, inputs, &now)
}
