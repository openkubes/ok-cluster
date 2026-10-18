package bootstrapcheck

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func observerFixture(t *testing.T, role string) (fixture, ObserverInputs, Result, ObserverBudget) {
	t.Helper()
	f := newFixture(t)
	f.r.Binding.Role = role
	inputs := ObserverInputs{Expected: f.r.Binding, OperationNonce: "0123456789abcdef0123456789abcdef", CADER: f.c.CADER, PredecessorStage: 4, PredecessorReceiptDigest: f.r.Binding.Stage4ReceiptDigest}
	if role == "runtime-observer" {
		inputs.PredecessorStage = 5
		inputs.PredecessorReceiptDigest = hash([]byte("stage5-receipt"))
	}
	constraints, err := observerConstraints(inputs)
	if err != nil {
		t.Fatal(err)
	}
	f.c = constraints
	f.r.CSRDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: constraints.CommonName}}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	result := f.result(t, func(c *x509.Certificate) {
		c.NotBefore = f.now.Add(-time.Minute)
		c.NotAfter = f.now.Add(44 * time.Minute)
	})
	return f, inputs, result, ObserverBudget{f.now, 30 * time.Minute, time.Minute}
}

func TestApprovedLocalObserverProfile(t *testing.T) {
	for _, role := range []string{"network-observer", "runtime-observer"} {
		t.Run(role, func(t *testing.T) {
			f, inputs, result, budget := observerFixture(t, role)
			constraints, err := observerConstraints(inputs)
			if err != nil || constraints.CommonName != "ok147:0123456789abcdef0123456789abcdef:"+role || constraints.MaxValidity != 45*time.Minute || constraints.ClockSkew != 60*time.Second {
				t.Fatal("observer profile changed")
			}
			if err := ValidateObserverRequest(f.r, inputs); err != nil {
				t.Fatal(err)
			}
			// Initial 60-second backdating does not become a 60-second deadline
			// for entering the stage: the independent handoff budget is 5 minutes.
			for _, delay := range []time.Duration{0, time.Minute, 5 * time.Minute} {
				if err := ValidateObserverStageEntry(f.r, result, inputs, budget, f.now.Add(delay)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestObserverIdentityNegatives(t *testing.T) {
	for _, nonce := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), " " + strings.Repeat("a", 32)} {
		f, inputs, _, _ := observerFixture(t, "network-observer")
		inputs.OperationNonce = nonce
		if ValidateObserverRequest(f.r, inputs) == nil {
			t.Fatal("accepted invalid nonce")
		}
	}
	f, inputs, result, budget := observerFixture(t, "network-observer")
	inputs.OperationNonce = strings.Repeat("b", 32)
	if ValidateObserverRequest(f.r, inputs) == nil || ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
		t.Fatal("accepted another operation nonce")
	}
	f, inputs, result, budget = observerFixture(t, "network-observer")
	inputs.Expected.Role = "runtime-observer"
	f.r.Binding.Role = inputs.Expected.Role
	inputs.PredecessorStage = 5
	inputs.PredecessorReceiptDigest = hash([]byte("stage5-receipt"))
	result.RequestDigest, _ = RequestDigest(f.r)
	if ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
		t.Fatal("accepted cross-role certificate despite rewritten request digest")
	}
	for _, role := range []string{"fixed-probe", "target-access-installer", "system:masters"} {
		f, inputs, result, budget = observerFixture(t, "network-observer")
		inputs.Expected.Role = role
		f.r.Binding.Role = role
		if ValidateObserverRequest(f.r, inputs) == nil || ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
			t.Fatal("accepted non-observer role")
		}
	}
}

func TestObserverCertificateProfileNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*x509.Certificate){
		"over 45 minutes":         func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(45*time.Minute + time.Second) },
		"over 60 second backdate": func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(-time.Second) },
		"future NotBefore":        func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(61 * time.Second) },
		"certificate groups":      func(c *x509.Certificate) { c.Subject.Organization = []string{"observers"} },
		"short certificate":       func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(10 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			f, inputs, _, budget := observerFixture(t, "network-observer")
			result := f.result(t, func(c *x509.Certificate) {
				c.NotBefore = f.now.Add(-time.Minute)
				c.NotAfter = f.now.Add(44 * time.Minute)
				mutate(c)
			})
			if ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
				t.Fatal("accepted invalid observer certificate")
			}
		})
	}
}

func TestObserverStageBudgetNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*ObserverBudget, *time.Time){
		"zero issuance":          func(b *ObserverBudget, _ *time.Time) { b.IssuedAt = time.Time{} },
		"future issuance":        func(b *ObserverBudget, now *time.Time) { b.IssuedAt = now.Add(time.Second) },
		"zero stage clock":       func(_ *ObserverBudget, now *time.Time) { *now = time.Time{} },
		"late handoff":           func(_ *ObserverBudget, now *time.Time) { *now = now.Add(5*time.Minute + time.Nanosecond) },
		"zero polling":           func(b *ObserverBudget, _ *time.Time) { b.PollTimeout = 0 },
		"negative polling":       func(b *ObserverBudget, _ *time.Time) { b.PollTimeout = -time.Second },
		"over 30 minute polling": func(b *ObserverBudget, _ *time.Time) { b.PollTimeout = 30*time.Minute + time.Nanosecond },
		"missing overhead":       func(b *ObserverBudget, _ *time.Time) { b.WrapperOverhead = 0 },
		"negative overhead":      func(b *ObserverBudget, _ *time.Time) { b.WrapperOverhead = -time.Second },
		"overflow overhead":      func(b *ObserverBudget, _ *time.Time) { b.WrapperOverhead = time.Duration(1<<63 - 1) },
		"NotAfter equality":      func(b *ObserverBudget, _ *time.Time) { b.WrapperOverhead = 14 * time.Minute },
		"insufficient lifetime":  func(b *ObserverBudget, _ *time.Time) { b.WrapperOverhead = 15 * time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			f, inputs, result, budget := observerFixture(t, "runtime-observer")
			now := f.now
			mutate(&budget, &now)
			if ValidateObserverStageEntry(f.r, result, inputs, budget, now) == nil {
				t.Fatal("accepted invalid stage window")
			}
		})
	}
	f, inputs, result, budget := observerFixture(t, "runtime-observer")
	budget.WrapperOverhead = 14*time.Minute - time.Nanosecond
	if err := ValidateObserverStageEntry(f.r, result, inputs, budget, f.now); err != nil {
		t.Fatal("strictly sufficient remaining lifetime rejected", err)
	}
}

func TestGenericResultFreshnessWasNotRelaxed(t *testing.T) {
	f, inputs, result, budget := observerFixture(t, "runtime-observer")
	if ValidateResult(f.r, result, f.c, f.now.Add(2*time.Minute)) == nil {
		t.Fatal("existing initial-result freshness check was relaxed")
	}
	if err := ValidateObserverStageEntry(f.r, result, inputs, budget, f.now.Add(2*time.Minute)); err != nil {
		t.Fatal("separate authenticated-issuance check rejected valid stage entry", err)
	}
	result.RequestDigest = hash([]byte("other request"))
	if ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
		t.Fatal("stage entry accepted result binding drift")
	}
}

func TestObserverRequiresRoleSpecificPredecessor(t *testing.T) {
	for _, role := range []string{"network-observer", "runtime-observer"} {
		for _, which := range []string{"missing digest", "wrong stage", "wrong network prefix"} {
			t.Run(role+"/"+which, func(t *testing.T) {
				f, inputs, result, budget := observerFixture(t, role)
				switch which {
				case "missing digest":
					inputs.PredecessorReceiptDigest = ""
				case "wrong stage":
					inputs.PredecessorStage = 3
				case "wrong network prefix":
					if role != "network-observer" {
						return
					}
					inputs.PredecessorReceiptDigest = hash([]byte("other prefix"))
				}
				if ValidateObserverRequest(f.r, inputs) == nil || ValidateObserverStageEntry(f.r, result, inputs, budget, f.now) == nil {
					t.Fatal("accepted missing/wrong predecessor expectation")
				}
			})
		}
	}
}

func TestObserverRejectsLossyJSONBindingStrings(t *testing.T) {
	for _, value := range []string{"invalid-\xff-uid", "control-\n-uid"} {
		f, inputs, _, _ := observerFixture(t, "network-observer")
		f.r.Binding.SourceUID = value
		inputs.Expected = f.r.Binding
		if ValidateObserverRequest(f.r, inputs) == nil {
			t.Fatal("accepted ambiguous binding string")
		}
	}
}
