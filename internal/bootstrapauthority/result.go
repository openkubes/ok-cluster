package bootstrapauthority

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

// SignedResult contains only a public leaf certificate, never a private key.
// Request-delegation and result-attestation keys are distinct in Trust.
type SignedResult struct {
	Audience, KeyID, SlotDigest, ClaimDigest, AuthorizationDigest string
	Result                                                        bootstrapcheck.Result
	IssuedAt                                                      time.Time
	Signature                                                     []byte
}

func ResultSigningBytes(r SignedResult) ([]byte, error) {
	if len(r.Result.CertificateDER) == 0 || len(r.Result.CertificateDER) > 65536 {
		return nil, errors.New("invalid issuer result size")
	}
	return json.Marshal(struct{ Domain, Audience, KeyID, Slot, Claim, Authorization, Request, Certificate, IssuedAt string }{"ok147-bootstrap-result-signature-candidate/v1", r.Audience, r.KeyID, r.SlotDigest, r.ClaimDigest, r.AuthorizationDigest, r.Result.RequestDigest, digest(r.Result.CertificateDER), r.IssuedAt.UTC().Format(time.RFC3339Nano)})
}

type resultRecord struct {
	Domain, ClaimDigest string
	Result              SignedResult
	CompletedAt         time.Time
}

func (a *Authority) verifyResult(r VerifiedRequest, claim claimRecord, claimDigest string, result SignedResult, now time.Time) error {
	if result.Audience != ResultAudience || result.KeyID != digest(a.trust.ResultPublicKey) || result.SlotDigest != r.slotDigest || result.ClaimDigest != claimDigest || result.AuthorizationDigest != r.authorizationDigest || result.IssuedAt.Before(claim.ClaimedAt) || !result.IssuedAt.Before(r.request.NotAfter) {
		return ErrStop
	}
	message, err := ResultSigningBytes(result)
	if err != nil || !ed25519.Verify(a.trust.ResultPublicKey, message, result.Signature) {
		return ErrStop
	}
	if bootstrapcheck.ValidateObserverStageEntry(r.request.Request, result.Result, r.inputs, bootstrapcheck.ObserverBudget{IssuedAt: result.IssuedAt, PollTimeout: r.request.PollTimeout, WrapperOverhead: r.request.WrapperOverhead}, now) != nil {
		return ErrStop
	}
	return nil
}

// Complete only persists an already signed/verified candidate result. There is
// no signing callback. Unknown write outcomes remain STOP; no write is retried.
func (a *Authority) Complete(ctx context.Context, claim Claim, result SignedResult, now time.Time) error {
	if !a.validVerified(claim.request) {
		return ErrStop
	}
	stored, claimDigest, err := a.readClaim(ctx, claim.request)
	if err != nil || stored != claim.record || claimDigest != claim.digest || a.verifyResult(claim.request, stored, claimDigest, result, now) != nil {
		return ErrStop
	}
	result.IssuedAt = result.IssuedAt.UTC()
	result.Result.CertificateDER = append([]byte(nil), result.Result.CertificateDER...)
	result.Signature = append([]byte(nil), result.Signature...)
	record := resultRecord{"ok147-bootstrap-result-record-candidate/v1", claimDigest, result, now.UTC()}
	raw, _ := json.Marshal(record)
	if err := a.store.CreateResult(ctx, claim.request.slotDigest, raw); err != nil {
		if !errors.Is(err, ErrExists) {
			return ErrStop
		}
		// Known conflict permits an exact-result read, never replacement/retry.
		existing, err := a.store.ReadResult(ctx, claim.request.slotDigest)
		var old resultRecord
		if err != nil || decodeRecord(existing, &old) != nil || old.Domain != record.Domain || old.ClaimDigest != record.ClaimDigest || old.CompletedAt.Before(stored.ClaimedAt) || a.verifyResult(claim.request, stored, claimDigest, old.Result, old.CompletedAt) != nil {
			return ErrStop
		}
		before, _ := json.Marshal(old.Result)
		after, _ := json.Marshal(result)
		if string(before) != string(after) {
			return ErrStop
		}
	}
	return nil
}
