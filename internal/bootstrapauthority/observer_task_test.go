package bootstrapauthority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

type observerTaskFixture struct {
	f             fixture
	config        ObserverTaskConfig
	source        ObserverTaskSource
	reads, issues int
	result        SignedResult
	storeReads    atomic.Int32
}

type observerTaskReadSpy struct {
	Store
	reads *atomic.Int32
}

func (s observerTaskReadSpy) ReadClaim(ctx context.Context, slot string) ([]byte, error) {
	s.reads.Add(1)
	return s.Store.ReadClaim(ctx, slot)
}

func (s observerTaskReadSpy) ReadResult(ctx context.Context, slot string) ([]byte, error) {
	s.reads.Add(1)
	return s.Store.ReadResult(ctx, slot)
}

func newObserverTaskFixture(t *testing.T, role string) *observerTaskFixture {
	t.Helper()
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
	s := newSourceContractFixture(t, f)
	tf := &observerTaskFixture{f: f, source: ObserverTaskSource{s.metadata, s.caDER, s.keyPEM}}
	tf.config = ObserverTaskConfig{
		Authority: f.a, Inputs: f.inputs, SourceOwner: s.owner, Clock: func() time.Time { return f.now },
		ReadSource: func(_ context.Context, b bootstrapcheck.Binding) (ObserverTaskSource, error) {
			tf.reads++
			if b != f.inputs.Expected {
				t.Fatal("reader received a caller-selected source")
			}
			return tf.source, nil
		},
		IssueResult: func(ctx context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
			tf.issues++
			state, err := f.a.Inspect(ctx, f.r, f.inputs)
			if err != nil || state.State != "CLAIMED_INDETERMINATE_STOP" || f.store.claimWrites != 1 || f.store.resultWrites != 0 || tf.reads != 2 {
				t.Fatalf("issuer ran without one claim and two source checks: state=%s reads=%d err=%v", state.State, tf.reads, err)
			}
			if !input.IssuedAt.Equal(f.now) || input.Request.Binding != f.r.Request.Binding || !bytes.Equal(input.Request.CSRDER, f.r.Request.CSRDER) || !bytes.Equal(input.Source.PrivateKeyPEM, tf.source.PrivateKeyPEM) || input.Inputs.Expected != f.inputs.Expected || input.PollTimeout != f.r.PollTimeout || input.Overhead != f.r.WrapperOverhead {
				t.Fatal("issuer input differs from authenticated frozen request")
			}
			tf.result = f.result(t, input.Claim) // In-memory synthetic signing only.
			return tf.result, nil
		},
	}
	wrapped, err := New(f.trust, observerTaskReadSpy{Store: f.store, reads: &tf.storeReads})
	if err != nil {
		t.Fatal(err)
	}
	tf.config.Authority = wrapped
	return tf
}

func openObserverTask(t *testing.T, tf *observerTaskFixture) *ObserverTask {
	t.Helper()
	task, err := NewObserverTask(tf.config)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func assertStoppedObserverResult(t *testing.T, result SignedResult, err error) {
	t.Helper()
	if !reflect.DeepEqual(result, SignedResult{}) || !errors.Is(err, ErrStop) || strings.Contains(err.Error(), "SENSITIVE_ADAPTER") {
		t.Fatalf("failure returned material, lost STOP or leaked a diagnostic: empty=%v err=%v", reflect.DeepEqual(result, SignedResult{}), err)
	}
}

func TestObserverTaskCancellationAfterIssuanceDoesNotDeliver(t *testing.T) {
	tf := newObserverTaskFixture(t, "network-observer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	issue := tf.config.IssueResult
	tf.config.IssueResult = func(ctx context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
		result, err := issue(ctx, input)
		cancel()
		return result, err
	}
	result, err := openObserverTask(t, tf).Run(ctx, tf.f.r)
	assertStoppedObserverResult(t, result, err)
	if tf.issues != 1 {
		t.Fatal("cancellation fixture did not reach issuance")
	}
	assertSourceContractStore(t, tf.f, 1, 0)
}

func TestObserverTaskPersistsBeforeDeliveryAndNeverReplays(t *testing.T) {
	for _, role := range []string{"network-observer", "runtime-observer"} {
		t.Run(role, func(t *testing.T) {
			tf := newObserverTaskFixture(t, role)
			task := openObserverTask(t, tf)
			result, err := task.Run(context.Background(), tf.f.r)
			if err != nil || len(result.Result.CertificateDER) == 0 || tf.reads != 2 || tf.issues != 1 {
				t.Fatalf("task did not complete exact bounded flow: reads=%d issues=%d err=%v", tf.reads, tf.issues, err)
			}
			assertSourceContractStore(t, tf.f, 1, 1)
			state, err := tf.f.a.Inspect(context.Background(), tf.f.r, tf.f.inputs)
			if err != nil || state.State != "RESULT_RECORDED_NOT_STAGE_AUTHORIZED" || state.Result == nil || !bytes.Equal(state.Result.Result.CertificateDER, result.Result.CertificateDER) {
				t.Fatalf("delivery preceded verified persistence: state=%s err=%v", state.State, err)
			}
			// Mutating the adapter's retained return value cannot alter delivery.
			tf.result.Result.CertificateDER[0] ^= 1
			tf.result.Signature[0] ^= 1
			if !bytes.Equal(state.Result.Result.CertificateDER, result.Result.CertificateDER) || !bytes.Equal(state.Result.Signature, result.Signature) {
				t.Fatal("delivered result aliases adapter memory")
			}
			for _, again := range []*ObserverTask{task, openObserverTask(t, tf)} {
				output, err := again.Run(context.Background(), tf.f.r)
				if !errors.Is(err, ErrConsumed) || !reflect.DeepEqual(output, SignedResult{}) || tf.reads != 2 || tf.issues != 1 {
					t.Fatalf("task redelivered/reissued or reread a consumed source: %v", err)
				}
			}
		})
	}
}

func TestObserverTaskRejectsUnsupportedRequestBeforeAdapters(t *testing.T) {
	for _, name := range []string{"signature", "target", "oversized CSR", "zero clock", "cancelled", "nil context"} {
		t.Run(name, func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			r := tf.f.r
			ctx := context.Background()
			switch name {
			case "signature":
				r.Signature = append([]byte(nil), r.Signature...)
				r.Signature[0] ^= 1
			case "target":
				tf.f.r.Request.Binding.TargetUID, tf.f.r.Request.Binding.SourceOwnerUID = "foreign", "foreign"
				tf.f.signRequest(t)
				r = tf.f.r
			case "oversized CSR":
				r.Request.CSRDER = bytes.Repeat([]byte{1}, 16385)
			case "zero clock":
				tf.config.Clock = func() time.Time { return time.Time{} }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil context":
				ctx = nil
			}
			task := openObserverTask(t, tf)
			result, err := task.Run(ctx, r)
			assertStoppedObserverResult(t, result, err)
			if tf.reads != 0 || tf.issues != 0 || tf.storeReads.Load() != 0 {
				t.Fatal("rejected request reached an adapter or coordination read")
			}
			assertSourceContractStore(t, tf.f, 0, 0)
			if _, err := task.Run(context.Background(), tf.f.r); !errors.Is(err, ErrConsumed) {
				t.Fatal("failed task instance was reset")
			}
		})
	}
}

func TestObserverTaskStopsAtEachEffectBoundary(t *testing.T) {
	for _, name := range []string{"store read", "source before claim", "first source drift", "claim unknown uncommitted", "claim unknown committed", "source after claim", "second source drift", "issuer error", "result unknown uncommitted", "result unknown committed", "bad result signature", "bad issuance time", "oversized result"} {
		t.Run(name, func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			wantReads, wantIssues, wantClaims, wantResults := 2, 1, 1, 0
			read, issue := tf.config.ReadSource, tf.config.IssueResult
			switch name {
			case "store read":
				tf.f.store.failRead = true
				wantReads, wantIssues, wantClaims = 0, 0, 0
			case "source before claim", "first source drift", "source after claim", "second source drift":
				after := name == "source after claim" || name == "second source drift"
				wantIssues = 0
				if !after {
					wantReads, wantClaims = 1, 0
				}
				tf.config.ReadSource = func(ctx context.Context, b bootstrapcheck.Binding) (ObserverTaskSource, error) {
					s, err := read(ctx, b)
					if (!after && tf.reads == 1) || (after && tf.reads == 2) {
						if strings.Contains(name, "drift") {
							s.Metadata = bytes.ReplaceAll(s.Metadata, []byte(`"resourceVersion":"123"`), []byte(`"resourceVersion":"124"`))
						} else {
							return ObserverTaskSource{}, errors.New("SENSITIVE_ADAPTER source")
						}
					}
					return s, err
				}
			case "claim unknown uncommitted", "claim unknown committed":
				tf.f.store.failClaim, tf.f.store.commitClaim = true, name == "claim unknown committed"
				wantReads, wantIssues = 1, 0
			case "issuer error":
				tf.config.IssueResult = func(ctx context.Context, in ObserverTaskIssueInput) (SignedResult, error) {
					partial, _ := issue(ctx, in)
					return partial, errors.New("SENSITIVE_ADAPTER issuer")
				}
			case "result unknown uncommitted", "result unknown committed":
				tf.f.store.failResult, tf.f.store.commitResult = true, name == "result unknown committed"
				wantResults = 1
			case "bad result signature", "bad issuance time", "oversized result":
				if name == "bad issuance time" {
					calls := 0
					tf.config.Clock = func() time.Time {
						calls++
						if calls >= 5 {
							return tf.f.now.Add(2 * time.Second)
						}
						return tf.f.now
					}
				}
				tf.config.IssueResult = func(ctx context.Context, in ObserverTaskIssueInput) (SignedResult, error) {
					r, err := issue(ctx, in)
					switch name {
					case "bad result signature":
						r.Signature[0] ^= 1
					case "bad issuance time":
						r.IssuedAt = r.IssuedAt.Add(time.Second)
						template, parseErr := x509.ParseCertificate(r.Result.CertificateDER)
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						template.NotBefore, template.NotAfter = r.IssuedAt.Add(-time.Minute), r.IssuedAt.Add(44*time.Minute)
						r.Result.CertificateDER, parseErr = x509.CreateCertificate(rand.Reader, template, tf.f.ca, tf.f.leafKey.Public(), tf.f.caKey)
						if parseErr != nil {
							t.Fatal(parseErr)
						}
						tf.f.signResult(t, &r)
						if entryErr := bootstrapcheck.ValidateObserverStageEntry(tf.f.r.Request, r.Result, tf.f.inputs, bootstrapcheck.ObserverBudget{
							IssuedAt: r.IssuedAt, PollTimeout: tf.f.r.PollTimeout, WrapperOverhead: tf.f.r.WrapperOverhead,
						}, tf.f.now.Add(2*time.Second)); entryErr != nil {
							t.Fatalf("timestamp fixture shadowed by another certificate failure: %v", entryErr)
						}
					case "oversized result":
						r.Result.CertificateDER = make([]byte, 65537)
					}
					return r, err
				}
			}
			task := openObserverTask(t, tf)
			result, err := task.Run(context.Background(), tf.f.r)
			assertStoppedObserverResult(t, result, err)
			if tf.reads != wantReads || tf.issues != wantIssues {
				t.Fatalf("crossed effect boundary: reads=%d issues=%d", tf.reads, tf.issues)
			}
			assertSourceContractStore(t, tf.f, wantClaims, wantResults)
			if _, err := task.Run(context.Background(), tf.f.r); !errors.Is(err, ErrConsumed) {
				t.Fatal("uncertain task automatically replayed")
			}
		})
	}
}

func TestObserverTaskClockAndCancellationBoundaries(t *testing.T) {
	for _, phase := range []int{2, 3, 4, 5} {
		for _, backwards := range []bool{false, true} {
			t.Run(fmt.Sprintf("phase-%d/backwards-%t", phase, backwards), func(t *testing.T) {
				tf := newObserverTaskFixture(t, "network-observer")
				if backwards {
					tf.config.IssueResult = func(_ context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
						tf.issues++
						at := tf.f
						at.now = input.IssuedAt
						return at.result(t, input.Claim), nil
					}
				}
				calls := 0
				tf.config.Clock = func() time.Time {
					calls++
					if calls >= phase {
						if backwards {
							return tf.f.now.Add(30 * time.Second)
						}
						return tf.f.r.NotAfter
					}
					if backwards {
						return tf.f.now.Add(time.Minute)
					}
					return tf.f.now
				}
				result, err := openObserverTask(t, tf).Run(context.Background(), tf.f.r)
				assertStoppedObserverResult(t, result, err)
				if backwards && !strings.Contains(err.Error(), "observer task clock:") {
					t.Fatalf("clock regression was shadowed by a later denial: %v", err)
				}
				wantIssues := 0
				if phase == 5 {
					wantIssues = 1
				}
				if tf.issues != wantIssues {
					t.Fatalf("wrong issue boundary at clock call %d: %d", phase, tf.issues)
				}
				if tf.f.store.resultWrites != 0 {
					t.Fatal("expired/regressed clock persisted a result")
				}
			})
		}
	}
	tf := newObserverTaskFixture(t, "network-observer")
	ctx, cancel := context.WithCancel(context.Background())
	read := tf.config.ReadSource
	tf.config.ReadSource = func(ctx context.Context, b bootstrapcheck.Binding) (ObserverTaskSource, error) {
		s, err := read(ctx, b)
		cancel()
		return s, err
	}
	result, err := openObserverTask(t, tf).Run(ctx, tf.f.r)
	assertStoppedObserverResult(t, result, err)
	assertSourceContractStore(t, tf.f, 0, 0)
}

func TestObserverTaskConcurrentCallsHaveOneWinner(t *testing.T) {
	tf := newObserverTaskFixture(t, "network-observer")
	task := openObserverTask(t, tf)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := task.Run(context.Background(), tf.f.r)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrConsumed) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || tf.reads != 2 || tf.issues != 1 {
		t.Fatalf("concurrent task duplicated effects: successes=%d reads=%d issues=%d", successes.Load(), tf.reads, tf.issues)
	}
	assertSourceContractStore(t, tf.f, 1, 1)
}

func TestObserverTaskConcurrentInstancesShareOneDurableClaim(t *testing.T) {
	tf := newObserverTaskFixture(t, "network-observer")
	var issues, successes atomic.Int32
	tf.config.ReadSource = func(context.Context, bootstrapcheck.Binding) (ObserverTaskSource, error) {
		return tf.source, nil
	}
	tf.config.IssueResult = func(_ context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
		issues.Add(1)
		return tf.f.result(t, input.Claim), nil
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		task := openObserverTask(t, tf)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := task.Run(context.Background(), tf.f.r)
			if err == nil {
				successes.Add(1)
			} else if (!errors.Is(err, ErrConsumed) && !errors.Is(err, ErrStop)) || !reflect.DeepEqual(result, SignedResult{}) {
				t.Errorf("loser returned material or unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if issues.Load() != 1 || successes.Load() != 1 || len(tf.f.store.claims) != 1 || len(tf.f.store.results) != 1 {
		t.Fatalf("concurrent instances duplicated issuance/delivery: issues=%d successes=%d claims=%d results=%d", issues.Load(), successes.Load(), len(tf.f.store.claims), len(tf.f.store.results))
	}
}

func TestObserverTaskRejectsIncompleteConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*ObserverTaskConfig){
		"authority": func(c *ObserverTaskConfig) { c.Authority = nil },
		"reader":    func(c *ObserverTaskConfig) { c.ReadSource = nil },
		"issuer":    func(c *ObserverTaskConfig) { c.IssueResult = nil },
		"clock":     func(c *ObserverTaskConfig) { c.Clock = nil },
		"CA":        func(c *ObserverTaskConfig) { c.Inputs.CADER = nil },
		"large CA":  func(c *ObserverTaskConfig) { c.Inputs.CADER = make([]byte, 65537) },
		"bad DER":   func(c *ObserverTaskConfig) { c.Inputs.CADER = []byte("invalid") },
		"owner":     func(c *ObserverTaskConfig) { c.SourceOwner.Name = "" },
		"owner API": func(c *ObserverTaskConfig) { c.SourceOwner.APIVersion = "unsupported/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			mutate(&tf.config)
			task, err := NewObserverTask(tf.config)
			if task != nil || !errors.Is(err, ErrStop) || tf.reads != 0 || tf.issues != 0 {
				t.Fatalf("incomplete task constructed or accessed an adapter: %v", err)
			}
		})
	}
	for _, task := range []*ObserverTask{nil, {}} {
		result, err := task.Run(context.Background(), SignedRequest{})
		assertStoppedObserverResult(t, result, err)
	}
}

func TestObserverTaskFreezesBoundaryBytes(t *testing.T) {
	tf := newObserverTaskFixture(t, "network-observer")
	tf.config.Inputs.CADER = append([]byte(nil), tf.config.Inputs.CADER...)
	request := tf.f.r
	request.Request.CSRDER = append([]byte(nil), request.Request.CSRDER...)
	request.Signature = append([]byte(nil), request.Signature...)
	read, issue := tf.config.ReadSource, tf.config.IssueResult
	tf.config.ReadSource = func(ctx context.Context, b bootstrapcheck.Binding) (ObserverTaskSource, error) {
		s, err := read(ctx, b)
		if tf.reads == 1 {
			tf.config.Inputs.CADER[0] ^= 1
			request.Request.CSRDER[0] ^= 1
			request.Signature[0] ^= 1
		}
		return s, err
	}
	tf.config.IssueResult = func(ctx context.Context, in ObserverTaskIssueInput) (SignedResult, error) {
		r, err := issue(ctx, in)
		in.Request.CSRDER[0] ^= 1
		in.Inputs.CADER[0] ^= 1
		return r, err
	}
	task := openObserverTask(t, tf)
	if _, err := task.Run(context.Background(), request); err != nil {
		t.Fatalf("external buffer mutation changed frozen task inputs: %v", err)
	}
	assertSourceContractStore(t, tf.f, 1, 1)
}

func TestObserverTaskChecksCAWindowBeforeIssuer(t *testing.T) {
	for _, name := range []string{"expired", "future", "insufficient budget"} {
		t.Run(name, func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"},
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				NotBefore: tf.f.now.Add(-time.Hour), NotAfter: tf.f.now.Add(time.Hour)}
			switch name {
			case "expired":
				template.NotAfter = tf.f.now
			case "future":
				template.NotBefore = tf.f.now.Add(time.Second)
			case "insufficient budget":
				template.NotAfter = tf.f.now.Add(tf.f.r.PollTimeout + tf.f.r.WrapperOverhead)
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, tf.f.caKey.Public(), tf.f.caKey)
			if err != nil {
				t.Fatal(err)
			}
			tf.f.inputs.CADER = der
			tf.f.inputs.Expected.CADigest, tf.f.r.Request.Binding.CADigest = digest(der), digest(der)
			tf.f.signRequest(t)
			tf.source.CertificateDER = der
			tf.config.Inputs = tf.f.inputs
			tf.config.ReadSource = func(context.Context, bootstrapcheck.Binding) (ObserverTaskSource, error) {
				tf.reads++
				return tf.source, nil
			}
			tf.config.IssueResult = func(context.Context, ObserverTaskIssueInput) (SignedResult, error) {
				tf.issues++
				return SignedResult{}, errors.New("must not issue")
			}
			result, err := openObserverTask(t, tf).Run(context.Background(), tf.f.r)
			assertStoppedObserverResult(t, result, err)
			if tf.reads != 2 || tf.issues != 0 || !strings.Contains(err.Error(), "observer task CA ") {
				t.Fatalf("CA window rejected at wrong boundary: reads=%d issues=%d err=%v", tf.reads, tf.issues, err)
			}
			assertSourceContractStore(t, tf.f, 1, 0)
		})
	}
}

func TestObserverTaskNormalizesSignedClockDomain(t *testing.T) {
	tf := newObserverTaskFixture(t, "network-observer")
	tf.config.Clock = func() time.Time { return tf.f.now.In(time.FixedZone("fixture", 3600)) }
	issue := tf.config.IssueResult
	tf.config.IssueResult = func(ctx context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
		if input.IssuedAt.Location() != time.UTC {
			t.Fatal("task issuance timestamp did not use the UTC wall-clock domain")
		}
		return issue(ctx, input)
	}
	if _, err := openObserverTask(t, tf).Run(context.Background(), tf.f.r); err != nil {
		t.Fatal(err)
	}
}

func TestObserverTaskRejectsCAReuseAsStageOrEvidenceKey(t *testing.T) {
	for _, which := range []string{"stage", "evidence"} {
		t.Run(which, func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			trust := tf.f.trust
			if which == "stage" {
				trust.StageKeyID = digest(tf.f.caKey.Public().(ed25519.PublicKey))
			} else {
				trust.EvidenceKeyID = digest(tf.f.caKey.Public().(ed25519.PublicKey))
			}
			a, err := New(trust, tf.f.store)
			if err != nil {
				t.Fatal(err)
			}
			tf.config.Authority = a
			task, err := NewObserverTask(tf.config)
			if task != nil || !errors.Is(err, ErrStop) || tf.reads != 0 || tf.issues != 0 || !strings.Contains(err.Error(), "CA key separation") {
				t.Fatalf("CA crossed stage/evidence signing boundary: %v", err)
			}
			assertSourceContractStore(t, tf.f, 0, 0)
		})
	}
}

func TestObserverTaskBoundsAdapterContext(t *testing.T) {
	for _, shorterParent := range []bool{false, true} {
		t.Run(fmt.Sprint(shorterParent), func(t *testing.T) {
			tf := newObserverTaskFixture(t, "network-observer")
			ctx := context.Background()
			if shorterParent {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Minute)
				defer cancel()
			}
			parentDeadline, parentHasDeadline := ctx.Deadline()
			read, issue := tf.config.ReadSource, tf.config.IssueResult
			check := func(ctx context.Context) {
				t.Helper()
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > tf.f.r.NotAfter.Sub(tf.f.now) || (parentHasDeadline && deadline.After(parentDeadline)) {
					t.Fatal("adapter context missing or extending signed/parent window")
				}
			}
			tf.config.ReadSource = func(ctx context.Context, b bootstrapcheck.Binding) (ObserverTaskSource, error) {
				check(ctx)
				return read(ctx, b)
			}
			tf.config.IssueResult = func(ctx context.Context, input ObserverTaskIssueInput) (SignedResult, error) {
				check(ctx)
				return issue(ctx, input)
			}
			if _, err := openObserverTask(t, tf).Run(ctx, tf.f.r); err != nil {
				t.Fatal(err)
			}
		})
	}
}
