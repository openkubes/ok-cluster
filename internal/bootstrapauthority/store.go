package bootstrapauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

var (
	ErrExists   = errors.New("issuer record already exists")
	ErrNotFound = errors.New("issuer record not found")
	ErrConsumed = errors.New("issuer slot consumed; no reissuance")
	ErrStop     = errors.New("issuer state indeterminate or inconsistent; STOP")
)

// Store must provide linearizable exact-name reads and atomic immutable creates
// in a dedicated issuer domain. There is deliberately no update/delete/lease or
// fallback capability. It must not alias stage-grant or teardown records. Only
// local fake-API tests cover the Kubernetes adapter; production durability,
// writer isolation, RBAC/admission and anti-deletion fencing remain unproven.
type Store interface {
	DomainDigest() string
	CreateClaim(context.Context, string, []byte) error
	ReadClaim(context.Context, string) ([]byte, error)
	CreateResult(context.Context, string, []byte) error
	ReadResult(context.Context, string) ([]byte, error)
}

type Authority struct {
	trust Trust
	store Store
	id    string
}

func New(trust Trust, store Store) (*Authority, error) {
	if store == nil {
		return nil, errors.New("dedicated issuer store required")
	}
	v := reflect.ValueOf(store)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return nil, errors.New("dedicated issuer store required")
		}
	}
	if len(trust.RequestPublicKey) != ed25519.PublicKeySize || len(trust.ResultPublicKey) != ed25519.PublicKeySize || !validDigest(trust.StageKeyID) || !validDigest(trust.EvidenceKeyID) || !validDigest(trust.PolicyDigest) || !validDigest(trust.StoreDomainDigest) || store.DomainDigest() != trust.StoreDomainDigest || trust.MaxRequestLifetime <= 0 {
		return nil, errors.New("explicit independent issuer trust required")
	}
	keys := []string{digest(trust.RequestPublicKey), digest(trust.ResultPublicKey), trust.StageKeyID, trust.EvidenceKeyID}
	for i := range keys {
		for j := 0; j < i; j++ {
			if keys[i] == keys[j] {
				return nil, errors.New("issuer, stage and evidence keys must be distinct")
			}
		}
	}
	trust.RequestPublicKey = append(ed25519.PublicKey(nil), trust.RequestPublicKey...)
	trust.ResultPublicKey = append(ed25519.PublicKey(nil), trust.ResultPublicKey...)
	raw, _ := json.Marshal(struct {
		Domain        string
		Keys          []string
		Policy, Store string
		MaxLifetime   int64
	}{"ok147-bootstrap-authority-candidate", keys, trust.PolicyDigest, trust.StoreDomainDigest, int64(trust.MaxRequestLifetime)})
	return &Authority{trust, store, digest(raw)}, nil
}

type claimRecord struct {
	Domain, SlotDigest, AuthorizationDigest, PolicyDigest, KeyID string
	ClaimedAt                                                    time.Time
}

// Claim is opaque and bound to the creating Authority and verified request.
// It is not a certificate, stage grant, readiness result or reusable capability.
type Claim struct {
	record  claimRecord
	request VerifiedRequest
	digest  string
}

func (c Claim) Digest() string              { return c.digest }
func (c Claim) SlotDigest() string          { return c.record.SlotDigest }
func (c Claim) AuthorizationDigest() string { return c.record.AuthorizationDigest }

func decodeRecord(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > 256*1024 || jsonstrict.Decode(raw, target) != nil {
		return ErrStop
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrStop
	}
	return nil
}

func (a *Authority) validVerified(r VerifiedRequest) bool { return r.verified && r.authorityID == a.id }

func (a *Authority) Claim(ctx context.Context, r VerifiedRequest, now time.Time) (Claim, error) {
	if !a.validVerified(r) || now.IsZero() || now.Before(r.request.NotBefore) || !now.Before(r.request.NotAfter) {
		return Claim{}, ErrStop
	}
	state, err := a.inspectVerified(ctx, r)
	if err != nil {
		return Claim{}, err
	}
	if state.State != "EMPTY_NOT_AUTHORIZED" {
		return Claim{}, ErrConsumed
	}
	record := claimRecord{"ok147-bootstrap-claim-candidate/v1", r.slotDigest, r.authorizationDigest, a.trust.PolicyDigest, r.request.KeyID, now.UTC()}
	raw, err := json.Marshal(record)
	if err != nil {
		return Claim{}, ErrStop
	}
	if err := a.store.CreateClaim(ctx, r.slotDigest, raw); err != nil {
		if errors.Is(err, ErrExists) {
			return Claim{}, ErrConsumed
		}
		return Claim{}, ErrStop
	}
	return Claim{record, r, digest(raw)}, nil
}

func (a *Authority) readClaim(ctx context.Context, r VerifiedRequest) (claimRecord, string, error) {
	raw, err := a.store.ReadClaim(ctx, r.slotDigest)
	if err != nil {
		return claimRecord{}, "", err
	}
	var c claimRecord
	if decodeRecord(raw, &c) != nil || c.Domain != "ok147-bootstrap-claim-candidate/v1" || c.SlotDigest != r.slotDigest || c.AuthorizationDigest != r.authorizationDigest || c.PolicyDigest != a.trust.PolicyDigest || c.KeyID != r.request.KeyID || c.ClaimedAt.Before(r.request.NotBefore) || !c.ClaimedAt.Before(r.request.NotAfter) {
		return claimRecord{}, "", ErrStop
	}
	return c, digest(raw), nil
}

type Inspection struct {
	State  string
	Result *SignedResult
}

// Inspect is read-only, including for expired signed requests. Historical
// result retrieval never reopens a slot or authorizes use of expired access.
func (a *Authority) Inspect(ctx context.Context, r SignedRequest, inputs bootstrapcheck.ObserverInputs) (Inspection, error) {
	verified, err := a.verify(r, inputs, nil)
	if err != nil {
		return Inspection{}, err
	}
	return a.inspectVerified(ctx, verified)
}

func (a *Authority) inspectVerified(ctx context.Context, r VerifiedRequest) (Inspection, error) {
	claim, claimDigest, claimErr := a.readClaim(ctx, r)
	resultRaw, resultErr := a.store.ReadResult(ctx, r.slotDigest)
	if claimErr != nil && !errors.Is(claimErr, ErrNotFound) {
		return Inspection{}, ErrStop
	}
	if resultErr != nil && !errors.Is(resultErr, ErrNotFound) {
		return Inspection{}, ErrStop
	}
	if errors.Is(claimErr, ErrNotFound) {
		if !errors.Is(resultErr, ErrNotFound) {
			return Inspection{}, ErrStop
		}
		return Inspection{State: "EMPTY_NOT_AUTHORIZED"}, nil
	}
	if errors.Is(resultErr, ErrNotFound) {
		return Inspection{State: "CLAIMED_INDETERMINATE_STOP"}, nil
	}
	var result resultRecord
	if decodeRecord(resultRaw, &result) != nil || result.Domain != "ok147-bootstrap-result-record-candidate/v1" || result.ClaimDigest != claimDigest || result.CompletedAt.Before(claim.ClaimedAt) || a.verifyResult(r, claim, claimDigest, result.Result, result.CompletedAt) != nil {
		return Inspection{}, ErrStop
	}
	return Inspection{State: "RESULT_RECORDED_NOT_STAGE_AUTHORIZED", Result: &result.Result}, nil
}
