package bootstrapcheck

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

// All signing here is ephemeral, in-memory fixture generation. No production
// issuer, real key, file, kubeconfig, network or cluster is involved.
type fixture struct {
	r     Request
	c     Constraints
	now   time.Time
	ca    *x509.Certificate
	caKey ed25519.PrivateKey
	key   ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{PlanDigest: hash([]byte("plan")), Attempt: "fixture-attempt", TargetUID: "fixture-target-uid", Endpoint: "https://192.0.2.10:6443", PolicyDigest: hash([]byte("policy")), Stage4ReceiptDigest: hash([]byte("receipt")), Role: "network-observer", SourceNamespace: "fixture", SourceName: "fixture-ca", SourceUID: "fixture-secret-uid", SourceResourceVersion: "123", SourceOwnerUID: "fixture-target-uid", CADigest: hash(caDER)}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "fixture-operation-network-observer"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{Request{b, csr}, Constraints{b, "fixture-operation-network-observer", caDER, 10 * time.Minute, time.Minute}, now, ca, caKey, key}
}

func (f fixture) result(t *testing.T, mutate func(*x509.Certificate)) Result {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.c.CommonName}, NotBefore: f.now.Add(-30 * time.Second), NotAfter: f.now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca, f.key.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := RequestDigest(f.r)
	if err != nil {
		t.Fatal(err)
	}
	return Result{digest, der}
}

func TestOfflineHappyPathAndObserverRoles(t *testing.T) {
	for _, role := range []string{"network-observer", "runtime-observer"} {
		t.Run(role, func(t *testing.T) {
			f := newFixture(t)
			f.r.Binding.Role = role
			f.c.Expected.Role = role
			if err := ValidateRequest(f.r, f.c); err != nil {
				t.Fatal(err)
			}
			if err := ValidateResult(f.r, f.result(t, nil), f.c, f.now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEveryBindingFieldMustMatchIndependentEvidence(t *testing.T) {
	typ := reflect.TypeOf(Binding{})
	for i := 0; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			f := newFixture(t)
			reflect.ValueOf(&f.r.Binding).Elem().Field(i).SetString("different")
			if err := ValidateRequest(f.r, f.c); err == nil {
				t.Fatal("accepted binding drift")
			}
		})
	}
}

func TestRequestNegatives(t *testing.T) {
	cases := map[string]func(*fixture){
		"unset lifetime":    func(f *fixture) { f.c.MaxValidity = 0 },
		"negative skew":     func(f *fixture) { f.c.ClockSkew = -time.Second },
		"unbounded skew":    func(f *fixture) { f.c.ClockSkew = f.c.MaxValidity },
		"system subject":    func(f *fixture) { f.c.CommonName = "system:masters" },
		"missing subject":   func(f *fixture) { f.c.CommonName = "" },
		"wrong subject":     func(f *fixture) { f.c.CommonName = "other" },
		"invalid CSR":       func(f *fixture) { f.r.CSRDER = []byte("invalid") },
		"oversized CSR":     func(f *fixture) { f.r.CSRDER = make([]byte, 16385) },
		"bad CSR signature": func(f *fixture) { f.r.CSRDER = append([]byte(nil), f.r.CSRDER...); f.r.CSRDER[len(f.r.CSRDER)-1] ^= 1 },
		"wrong CA":          func(f *fixture) { f.c.CADER = newFixture(t).c.CADER },
		"invalid CA": func(f *fixture) {
			f.c.CADER = []byte("invalid")
			f.r.Binding.CADigest = hash(f.c.CADER)
			f.c.Expected.CADigest = f.r.Binding.CADigest
		},
		"privileged role":   func(f *fixture) { f.r.Binding.Role = "target-access-installer"; f.c.Expected.Role = f.r.Binding.Role },
		"probe role":        func(f *fixture) { f.r.Binding.Role = "fixed-probe"; f.c.Expected.Role = f.r.Binding.Role },
		"wrong owner":       func(f *fixture) { f.r.Binding.SourceOwnerUID = "other"; f.c.Expected = f.r.Binding },
		"missing receipt":   func(f *fixture) { f.r.Binding.Stage4ReceiptDigest = ""; f.c.Expected = f.r.Binding },
		"http endpoint":     func(f *fixture) { f.r.Binding.Endpoint = "http://192.0.2.10:6443"; f.c.Expected = f.r.Binding },
		"endpoint userinfo": func(f *fixture) { f.r.Binding.Endpoint = "https://user@192.0.2.10:6443"; f.c.Expected = f.r.Binding },
		"CSR groups": func(f *fixture) {
			f.r.CSRDER, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: f.c.CommonName, Organization: []string{"system:masters"}}}, f.key)
		},
		"CSR SAN": func(f *fixture) {
			f.r.CSRDER, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: f.c.CommonName}, DNSNames: []string{"other"}}, f.key)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(&f)
			if err := ValidateRequest(f.r, f.c); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestCertificateNegatives(t *testing.T) {
	cases := map[string]func(*x509.Certificate){
		"wrong subject": func(c *x509.Certificate) { c.Subject.CommonName = "other" },
		"extra group":   func(c *x509.Certificate) { c.Subject.Organization = []string{"system:masters"} },
		"extra OU":      func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"extra"} },
		"CA capability": func(c *x509.Certificate) { c.IsCA = true },
		"signing usage": func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign },
		"wrong EKU":     func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"extra EKU":     func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		"missing EKU":   func(c *x509.Certificate) { c.ExtKeyUsage = nil },
		"DNS SAN":       func(c *x509.Certificate) { c.DNSNames = []string{"other"} },
		"IP SAN":        func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
		"expired":       func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(time.Second) },
		"future":        func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(time.Minute) },
		"too long":      func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Hour) },
		"backdated":     func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(-2 * time.Minute) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := ValidateResult(f.r, f.result(t, mutate), f.c, f.now); err == nil {
				t.Fatal("accepted invalid certificate")
			}
		})
	}
}

func TestResultBindingKeyIssuerAndClock(t *testing.T) {
	for _, name := range []string{"request digest", "wrong key", "wrong issuer", "corrupt DER", "zero clock", "cross role"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			result := f.result(t, nil)
			now := f.now
			switch name {
			case "request digest":
				result.RequestDigest = hash([]byte("other"))
			case "wrong key":
				f.key = newFixture(t).key
				result = f.result(t, nil)
			case "wrong issuer":
				other := newFixture(t)
				other.key = f.key
				other.r = f.r
				other.c.CommonName = f.c.CommonName
				result = other.result(t, nil)
			case "corrupt DER":
				result.CertificateDER = []byte("invalid")
			case "zero clock":
				now = time.Time{}
			case "cross role":
				f.r.Binding.Role = "runtime-observer"
				f.c.Expected.Role = f.r.Binding.Role
			}
			if err := ValidateResult(f.r, result, f.c, now); err == nil {
				t.Fatal("accepted invalid result")
			}
		})
	}
}

func TestSlotDoesNotCreateNewOpportunityForChangedCSRPolicyOrSource(t *testing.T) {
	f := newFixture(t)
	slot, err := SlotDigest(f.r.Binding)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := RequestDigest(f.r)
	f.r.CSRDER = newFixture(t).r.CSRDER
	f.r.Binding.PolicyDigest = hash([]byte("changed-policy"))
	f.r.Binding.SourceResourceVersion = "456"
	again, err := SlotDigest(f.r.Binding)
	if err != nil || slot != again {
		t.Fatal("drift created a different coordination slot")
	}
	changed, _ := RequestDigest(f.r)
	if digest == changed {
		t.Fatal("changed request retained request digest")
	}
	for _, mutate := range []func(*Binding){func(b *Binding) { b.Attempt = "other" }, func(b *Binding) { b.TargetUID = "other"; b.SourceOwnerUID = "other" }, func(b *Binding) { b.Role = "runtime-observer" }, func(b *Binding) { b.PlanDigest = hash([]byte("other")) }} {
		b := f.r.Binding
		mutate(&b)
		different, err := SlotDigest(b)
		if err != nil || different == slot {
			t.Fatal("distinct operation reused coordination slot")
		}
	}
}

func TestMalformedInputsAndAdditionalCertificateCapabilities(t *testing.T) {
	if _, err := SlotDigest(Binding{}); err == nil {
		t.Fatal("accepted empty slot binding")
	}
	if _, err := RequestDigest(Request{}); err == nil {
		t.Fatal("accepted empty request")
	}
	for _, cn := range []string{"fixture\nname", "fixture name", "fíxture"} {
		f := newFixture(t)
		f.c.CommonName = cn
		if err := ValidateRequest(f.r, f.c); err == nil {
			t.Fatal("accepted non-profile subject")
		}
	}
	for _, endpoint := range []string{"https://192.0.2.10:0", "https://192.0.2.10:65536", "https://192.0.2.10:6443?", "https://192.0.2.10:6443/path", "https://192.0.2.10:6443#fragment"} {
		f := newFixture(t)
		f.r.Binding.Endpoint = endpoint
		f.c.Expected = f.r.Binding
		if err := ValidateRequest(f.r, f.c); err == nil {
			t.Fatal("accepted invalid endpoint")
		}
	}
	for _, mutate := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}} },
		func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		},
	} {
		f := newFixture(t)
		if err := ValidateResult(f.r, f.result(t, mutate), f.c, f.now); err == nil {
			t.Fatal("accepted extra certificate capability")
		}
	}
}
