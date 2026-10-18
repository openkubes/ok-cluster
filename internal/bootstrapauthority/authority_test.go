package bootstrapauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

// Test backend only: mutex models atomic immutable creates and survives
// Authority replacement in memory. This is not proof of production durability.
type memoryStore struct {
	mu                                                         sync.Mutex
	claims, results                                            map[string][]byte
	domain                                                     string
	claimWrites, resultWrites                                  int
	failClaim, failResult, commitClaim, commitResult, failRead bool
}

func newStore() *memoryStore {
	return &memoryStore{claims: map[string][]byte{}, results: map[string][]byte{}, domain: digest([]byte("fixture-store-domain"))}
}
func (s *memoryStore) DomainDigest() string { return s.domain }
func (s *memoryStore) read(ctx context.Context, key string, result bool) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRead {
		return nil, errors.New("fixture read failure")
	}
	m := s.claims
	if result {
		m = s.results
	}
	raw, ok := m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), raw...), nil
}
func (s *memoryStore) create(ctx context.Context, key string, raw []byte, result bool) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.claims
	fail, commit := s.failClaim, s.commitClaim
	if result {
		s.resultWrites++
		m = s.results
		fail, commit = s.failResult, s.commitResult
	} else {
		s.claimWrites++
	}
	if _, ok := m[key]; ok {
		return ErrExists
	}
	if !fail || commit {
		m[key] = append([]byte(nil), raw...)
	}
	if fail {
		return errors.New("fixture write outcome unknown")
	}
	return nil
}
func (s *memoryStore) CreateClaim(c context.Context, k string, v []byte) error {
	return s.create(c, k, v, false)
}
func (s *memoryStore) ReadClaim(c context.Context, k string) ([]byte, error) {
	return s.read(c, k, false)
}
func (s *memoryStore) CreateResult(c context.Context, k string, v []byte) error {
	return s.create(c, k, v, true)
}
func (s *memoryStore) ReadResult(c context.Context, k string) ([]byte, error) {
	return s.read(c, k, true)
}

type fixture struct {
	a                                     *Authority
	trust                                 Trust
	store                                 *memoryStore
	r                                     SignedRequest
	inputs                                bootstrapcheck.ObserverInputs
	now                                   time.Time
	requestKey, resultKey, caKey, leafKey ed25519.PrivateKey
	ca                                    *x509.Certificate
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	requestPub, requestKey := key(t)
	resultPub, resultKey := key(t)
	_, caKey := key(t)
	_, leafKey := key(t)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "0123456789abcdef0123456789abcdef"
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ok147:" + nonce + ":network-observer"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	b := bootstrapcheck.Binding{PlanDigest: digest([]byte("plan")), Attempt: "attempt-fixture", TargetUID: "cluster-fixture-uid", Endpoint: "https://192.0.2.10:6443", PolicyDigest: digest([]byte("policy")), Stage4ReceiptDigest: digest([]byte("stage4")), Role: "network-observer", SourceNamespace: "fixture", SourceName: "fixture-ca", SourceUID: "secret-fixture-uid", SourceResourceVersion: "123", SourceOwnerUID: "cluster-fixture-uid", CADigest: digest(caDER)}
	store := newStore()
	trust := Trust{RequestPublicKey: requestPub, ResultPublicKey: resultPub, StageKeyID: digest([]byte("stage-key")), EvidenceKeyID: digest([]byte("evidence-key")), PolicyDigest: b.PolicyDigest, StoreDomainDigest: store.domain, MaxRequestLifetime: 5 * time.Minute}
	a, err := New(trust, store)
	if err != nil {
		t.Fatal(err)
	}
	r := SignedRequest{Audience: RequestAudience, KeyID: digest(requestPub), StoreDomainDigest: store.domain, Request: bootstrapcheck.Request{Binding: b, CSRDER: csr}, OperationNonce: nonce, PredecessorStage: 4, PredecessorReceiptDigest: b.Stage4ReceiptDigest, NotBefore: now, NotAfter: now.Add(5 * time.Minute), PollTimeout: 30 * time.Minute, WrapperOverhead: time.Minute}
	f := fixture{a, trust, store, r, bootstrapcheck.ObserverInputs{Expected: b, OperationNonce: nonce, CADER: caDER, PredecessorStage: 4, PredecessorReceiptDigest: b.Stage4ReceiptDigest}, now, requestKey, resultKey, caKey, leafKey, ca}
	f.signRequest(t)
	return f
}
func (f *fixture) signRequest(t *testing.T) {
	t.Helper()
	raw, err := RequestSigningBytes(f.r)
	if err != nil {
		t.Fatal(err)
	}
	f.r.Signature = ed25519.Sign(f.requestKey, raw)
}
func (f fixture) verified(t *testing.T) VerifiedRequest {
	t.Helper()
	r, err := f.a.Verify(f.r, f.inputs, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f fixture) claim(t *testing.T) Claim {
	t.Helper()
	c, err := f.a.Claim(context.Background(), f.verified(t), f.now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func (f fixture) result(t *testing.T, c Claim) SignedResult {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ok147:" + f.inputs.OperationNonce + ":" + f.r.Request.Binding.Role}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(44 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, f.ca, f.leafKey.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest, err := bootstrapcheck.RequestDigest(f.r.Request)
	if err != nil {
		t.Fatal(err)
	}
	r := SignedResult{Audience: ResultAudience, KeyID: digest(f.trust.ResultPublicKey), SlotDigest: c.SlotDigest(), ClaimDigest: c.Digest(), AuthorizationDigest: c.AuthorizationDigest(), Result: bootstrapcheck.Result{RequestDigest: requestDigest, CertificateDER: cert}, IssuedAt: f.now}
	f.signResult(t, &r)
	return r
}
func (f fixture) signResult(t *testing.T, r *SignedResult) {
	t.Helper()
	raw, err := ResultSigningBytes(*r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = ed25519.Sign(f.resultKey, raw)
}

func TestLocalRequestClaimAndHistoricalResult(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	state, err := f.a.Inspect(ctx, f.r, f.inputs)
	if err != nil || state.State != "EMPTY_NOT_AUTHORIZED" {
		t.Fatal(state, err)
	}
	c := f.claim(t)
	state, err = f.a.Inspect(ctx, f.r, f.inputs)
	if err != nil || state.State != "CLAIMED_INDETERMINATE_STOP" {
		t.Fatal(state, err)
	}
	r := f.result(t, c)
	if err = f.a.Complete(ctx, c, r, f.now); err != nil {
		t.Fatal(err)
	}
	// Exact result persistence is idempotent; it is not a second issuance.
	if err = f.a.Complete(ctx, c, r, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	replacement, err := New(f.trust, f.store)
	if err != nil {
		t.Fatal(err)
	}
	state, err = replacement.Inspect(ctx, f.r, f.inputs)
	if err != nil || state.State != "RESULT_RECORDED_NOT_STAGE_AUTHORIZED" || state.Result == nil {
		t.Fatal(state, err)
	}
	if _, err = replacement.Verify(f.r, f.inputs, f.now.Add(time.Hour)); err == nil {
		t.Fatal("expired request reopened")
	}
	if _, err = replacement.Claim(ctx, f.verified(t), f.now.Add(time.Hour)); err == nil {
		t.Fatal("expired request consumed")
	}
	if _, err = f.a.Claim(ctx, f.verified(t), f.now); err != ErrConsumed {
		t.Fatal("second claim allowed", err)
	}
}

func TestConcurrentSingleWinnerAndCrashStop(t *testing.T) {
	f := newFixture(t)
	r := f.verified(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := New(f.trust, f.store)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err = a.Claim(context.Background(), r, f.now); err == nil {
				wins.Add(1)
			} else if err != ErrConsumed && err != ErrStop {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("single winner violated", wins.Load())
	}
	a, err := New(f.trust, f.store)
	if err != nil {
		t.Fatal(err)
	}
	state, err := a.Inspect(context.Background(), f.r, f.inputs)
	if err != nil || state.State != "CLAIMED_INDETERMINATE_STOP" {
		t.Fatal(state, err)
	}
	if _, err = a.Claim(context.Background(), r, f.now); err != ErrConsumed {
		t.Fatal("crash restarted issuance", err)
	}
}

func TestTrustAndOpaqueRequestBoundaries(t *testing.T) {
	for name, mutate := range map[string]func(*Trust){
		"request key length": func(x *Trust) { x.RequestPublicKey = nil },
		"result key length":  func(x *Trust) { x.ResultPublicKey = nil },
		"same issuer keys":   func(x *Trust) { x.ResultPublicKey = x.RequestPublicKey },
		"stage key reuse":    func(x *Trust) { x.StageKeyID = digest(x.RequestPublicKey) },
		"evidence key reuse": func(x *Trust) { x.EvidenceKeyID = digest(x.ResultPublicKey) },
		"same legacy keys":   func(x *Trust) { x.EvidenceKeyID = x.StageKeyID },
		"missing policy":     func(x *Trust) { x.PolicyDigest = "" },
		"missing window":     func(x *Trust) { x.MaxRequestLifetime = 0 },
		"wrong store domain": func(x *Trust) { x.StoreDomainDigest = digest([]byte("other")) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(&f.trust)
			if _, err := New(f.trust, f.store); err == nil {
				t.Fatal("accepted invalid trust")
			}
		})
	}
	f := newFixture(t)
	var absent *memoryStore
	if _, err := New(f.trust, absent); err == nil {
		t.Fatal("accepted typed nil store")
	}
	if _, err := New(f.trust, nil); err == nil {
		t.Fatal("accepted nil store")
	}
	if _, err := f.a.Claim(context.Background(), VerifiedRequest{}, f.now); err == nil {
		t.Fatal("zero verified request accepted")
	}
	if err := f.a.Complete(context.Background(), Claim{}, SignedResult{}, f.now); err == nil {
		t.Fatal("zero claim accepted")
	}
	other := newFixture(t)
	if _, err := other.a.Claim(context.Background(), f.verified(t), f.now); err == nil {
		t.Fatal("foreign authority request accepted")
	}
}

func TestSignedRequestNegativesNeverWrite(t *testing.T) {
	for name, mutate := range map[string]func(*fixture){
		"stage audience":          func(f *fixture) { f.r.Audience = "ok-cluster-staged-executor" },
		"result audience":         func(f *fixture) { f.r.Audience = ResultAudience },
		"wrong key ID":            func(f *fixture) { f.r.KeyID = digest(f.trust.ResultPublicKey) },
		"wrong domain":            func(f *fixture) { f.r.StoreDomainDigest = digest([]byte("other")) },
		"wrong policy":            func(f *fixture) { f.r.Request.Binding.PolicyDigest = digest([]byte("other")) },
		"not yet valid":           func(f *fixture) { f.r.NotBefore = f.now.Add(time.Second) },
		"expiry equality":         func(f *fixture) { f.r.NotAfter = f.now },
		"oversized window":        func(f *fixture) { f.r.NotAfter = f.now.Add(6 * time.Minute) },
		"wrong nonce":             func(f *fixture) { f.r.OperationNonce = strings.Repeat("b", 32) },
		"wrong predecessor":       func(f *fixture) { f.r.PredecessorReceiptDigest = digest([]byte("other")) },
		"wrong predecessor stage": func(f *fixture) { f.r.PredecessorStage = 5 },
		"long polling":            func(f *fixture) { f.r.PollTimeout = 31 * time.Minute },
		"missing overhead":        func(f *fixture) { f.r.WrapperOverhead = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(&f)
			f.signRequest(t)
			if _, err := f.a.Verify(f.r, f.inputs, f.now); err == nil {
				t.Fatal("accepted invalid signed request")
			}
			if f.store.claimWrites != 0 || f.store.resultWrites != 0 {
				t.Fatal("verification wrote store")
			}
		})
	}
	f := newFixture(t)
	f.r.Signature[0] ^= 1
	if _, err := f.a.Verify(f.r, f.inputs, f.now); err == nil {
		t.Fatal("bad signature accepted")
	}
	f = newFixture(t)
	raw, _ := RequestSigningBytes(f.r)
	f.r.Signature = ed25519.Sign(f.resultKey, raw)
	if _, err := f.a.Verify(f.r, f.inputs, f.now); err == nil {
		t.Fatal("result key authorized request")
	}
}

func TestChangedCSRStillConsumesSameSlot(t *testing.T) {
	f := newFixture(t)
	_ = f.claim(t)
	_, otherKey := key(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ok147:" + f.inputs.OperationNonce + ":network-observer"}}, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	f.r.Request.CSRDER = csr
	f.signRequest(t)
	verified, err := f.a.Verify(f.r, f.inputs, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Claim(context.Background(), verified, f.now); err == nil {
		t.Fatal("CSR change reopened slot")
	}
	if f.store.claimWrites != 1 {
		t.Fatal("attempted replacement claim")
	}
}

func TestSignedResultNegativesNeverPersist(t *testing.T) {
	for name, mutate := range map[string]func(*SignedResult){
		"audience":            func(r *SignedResult) { r.Audience = RequestAudience },
		"key":                 func(r *SignedResult) { r.KeyID = digest([]byte("other")) },
		"slot":                func(r *SignedResult) { r.SlotDigest = digest([]byte("other")) },
		"claim":               func(r *SignedResult) { r.ClaimDigest = digest([]byte("other")) },
		"authorization":       func(r *SignedResult) { r.AuthorizationDigest = digest([]byte("other")) },
		"request":             func(r *SignedResult) { r.Result.RequestDigest = digest([]byte("other")) },
		"before claim":        func(r *SignedResult) { r.IssuedAt = r.IssuedAt.Add(-time.Second) },
		"expired issuance":    func(r *SignedResult) { r.IssuedAt = r.IssuedAt.Add(5 * time.Minute) },
		"invalid certificate": func(r *SignedResult) { r.Result.CertificateDER = []byte("invalid") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c := f.claim(t)
			r := f.result(t, c)
			mutate(&r)
			f.signResult(t, &r)
			if f.a.Complete(context.Background(), c, r, f.now) == nil {
				t.Fatal("accepted invalid signed result")
			}
			if f.store.resultWrites != 0 {
				t.Fatal("invalid result persisted")
			}
		})
	}
	f := newFixture(t)
	c := f.claim(t)
	r := f.result(t, c)
	r.Signature[0] ^= 1
	if f.a.Complete(context.Background(), c, r, f.now) == nil {
		t.Fatal("bad result signature accepted")
	}
	f = newFixture(t)
	c = f.claim(t)
	r = f.result(t, c)
	raw, _ := ResultSigningBytes(r)
	r.Signature = ed25519.Sign(f.requestKey, raw)
	if f.a.Complete(context.Background(), c, r, f.now) == nil {
		t.Fatal("request key attested result")
	}
}

func TestUnknownWriteOutcomeHasNoAutomaticRetry(t *testing.T) {
	for _, committed := range []bool{false, true} {
		f := newFixture(t)
		f.store.failClaim = true
		f.store.commitClaim = committed
		if _, err := f.a.Claim(context.Background(), f.verified(t), f.now); err != ErrStop {
			t.Fatal(err)
		}
		if f.store.claimWrites != 1 {
			t.Fatal("claim automatically retried")
		}
		if committed {
			f.store.failClaim = false
			state, err := f.a.Inspect(context.Background(), f.r, f.inputs)
			if err != nil || state.State != "CLAIMED_INDETERMINATE_STOP" {
				t.Fatal(state, err)
			}
		}
		f = newFixture(t)
		c := f.claim(t)
		r := f.result(t, c)
		f.store.failResult = true
		f.store.commitResult = committed
		if f.a.Complete(context.Background(), c, r, f.now) != ErrStop {
			t.Fatal("unknown result write not STOP")
		}
		if f.store.resultWrites != 1 {
			t.Fatal("result automatically retried")
		}
		state, err := f.a.Inspect(context.Background(), f.r, f.inputs)
		if err != nil {
			t.Fatal(err)
		}
		want := "CLAIMED_INDETERMINATE_STOP"
		if committed {
			want = "RESULT_RECORDED_NOT_STAGE_AUTHORIZED"
		}
		if state.State != want {
			t.Fatal(state)
		}
	}
}

func TestStoreDriftAndOrphansFailClosed(t *testing.T) {
	f := newFixture(t)
	c := f.claim(t)
	r := f.result(t, c)
	ctx := context.Background()
	if err := f.a.Complete(ctx, c, r, f.now); err != nil {
		t.Fatal(err)
	}
	slot := c.SlotDigest()
	originalClaim := append([]byte(nil), f.store.claims[slot]...)
	originalResult := append([]byte(nil), f.store.results[slot]...)
	for _, corrupt := range []func(){
		func() { delete(f.store.claims, slot) },
		func() { f.store.claims[slot] = []byte("invalid") },
		func() { f.store.results[slot] = []byte("invalid") },
		func() { f.store.results[slot] = append(originalResult, []byte("{}")...) },
		func() {
			var x resultRecord
			_ = json.Unmarshal(originalResult, &x)
			x.Result.AuthorizationDigest = digest([]byte("other"))
			f.store.results[slot], _ = json.Marshal(x)
		},
	} {
		f.store.claims[slot] = append([]byte(nil), originalClaim...)
		f.store.results[slot] = append([]byte(nil), originalResult...)
		corrupt()
		if _, err := f.a.Inspect(ctx, f.r, f.inputs); err != ErrStop {
			t.Fatal("accepted store drift/orphan", err)
		}
	}
	f = newFixture(t)
	f.store.failRead = true
	if _, err := f.a.Claim(ctx, f.verified(t), f.now); err != ErrStop || f.store.claimWrites != 0 {
		t.Fatal("read error allowed claim", err)
	}
}

func TestFrozenRequestAndResultCollision(t *testing.T) {
	f := newFixture(t)
	verified := f.verified(t)
	f.r.Request.CSRDER[0] ^= 1
	f.inputs.CADER[0] ^= 1
	c, err := f.a.Claim(context.Background(), verified, f.now)
	if err != nil {
		t.Fatal("caller mutation changed verified request", err)
	}
	// Build result using the frozen values, not caller-mutated slices.
	f.r = verified.request
	f.inputs = verified.inputs
	r := f.result(t, c)
	if err = f.a.Complete(context.Background(), c, r, f.now); err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(r.Result.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	certificate.SerialNumber = big.NewInt(3)
	r.Result.CertificateDER, err = x509.CreateCertificate(rand.Reader, certificate, f.ca, f.leafKey.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.signResult(t, &r)
	if f.a.Complete(context.Background(), c, r, f.now.Add(time.Second)) != ErrStop {
		t.Fatal("conflicting result replaced immutable record")
	}
	if f.store.resultWrites != 2 {
		t.Fatal("valid conflict fixture did not reach create-only result store")
	}
}

func TestRuntimeObserverAndAuthenticatedPredecessorBinding(t *testing.T) {
	f := newFixture(t)
	f.r.Request.Binding.Role = "runtime-observer"
	f.r.PredecessorStage = 5
	f.r.PredecessorReceiptDigest = digest([]byte("stage5"))
	f.inputs.Expected = f.r.Request.Binding
	f.inputs.PredecessorStage = 5
	f.inputs.PredecessorReceiptDigest = f.r.PredecessorReceiptDigest
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ok147:" + f.inputs.OperationNonce + ":runtime-observer"}}, f.leafKey)
	if err != nil {
		t.Fatal(err)
	}
	f.r.Request.CSRDER = csr
	f.signRequest(t)
	c := f.claim(t)
	if err := f.a.Complete(context.Background(), c, f.result(t, c), f.now); err != nil {
		t.Fatal(err)
	}
	f.r.PredecessorReceiptDigest = digest([]byte("different-stage5"))
	f.signRequest(t)
	if _, err = f.a.Verify(f.r, f.inputs, f.now); err == nil {
		t.Fatal("accepted predecessor drift against independent evidence")
	}
	f.inputs.PredecessorReceiptDigest = f.r.PredecessorReceiptDigest
	r, err := f.a.Verify(f.r, f.inputs, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Claim(context.Background(), r, f.now); err == nil {
		t.Fatal("newly authenticated predecessor reopened same slot")
	}
	if f.store.claimWrites != 1 {
		t.Fatal("predecessor change attempted a replacement claim")
	}
}

func TestStorageDomainAndConsumptionTimeAreExplicit(t *testing.T) {
	f := newFixture(t)
	other := newStore()
	other.domain = digest([]byte("other-storage-domain"))
	trust := f.trust
	trust.StoreDomainDigest = other.domain
	a, err := New(trust, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Verify(f.r, f.inputs, f.now); err == nil {
		t.Fatal("request crossed issuer store domain")
	}
	if _, err = f.a.Claim(context.Background(), f.verified(t), f.r.NotAfter); err == nil {
		t.Fatal("expiry boundary accepted at consumption")
	}
	if f.store.claimWrites != 0 || other.claimWrites != 0 {
		t.Fatal("rejected operation wrote store")
	}
}

func TestWorkloadCAIsNotAnIssuerAuthenticationKey(t *testing.T) {
	for _, which := range []string{"request", "result"} {
		f := newFixture(t)
		if which == "request" {
			f.trust.RequestPublicKey = f.caKey.Public().(ed25519.PublicKey)
			f.requestKey = f.caKey
			f.r.KeyID = digest(f.trust.RequestPublicKey)
		} else {
			f.trust.ResultPublicKey = f.caKey.Public().(ed25519.PublicKey)
		}
		a, err := New(f.trust, f.store)
		if err != nil {
			t.Fatal(err)
		}
		f.signRequest(t)
		if _, err = a.Verify(f.r, f.inputs, f.now); err == nil {
			t.Fatal("CA key reused for issuer authentication")
		}
	}
}
