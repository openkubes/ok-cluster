// Package bootstrapcheck contains experimental, offline-only checks for the
// proposed workload bootstrap contract. It is not wired into the CLI, runner,
// signer or transport and cannot authorize issuance or execution.
package bootstrapcheck

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Binding is an internal candidate model, not an accepted manifest/wire format.
// Expected values must come from independently verified platform/lifecycle
// evidence, never from the untrusted request/result itself.
type Binding struct {
	PlanDigest            string
	Attempt               string
	TargetUID             string
	Endpoint              string
	PolicyDigest          string
	Stage4ReceiptDigest   string
	Role                  string
	SourceNamespace       string
	SourceName            string
	SourceUID             string
	SourceResourceVersion string
	SourceOwnerUID        string
	CADigest              string
}

type Request struct {
	Binding Binding
	CSRDER  []byte
}

type Result struct {
	RequestDigest  string
	CertificateDER []byte
}

// Constraints has no lifetime, subject or trust defaults. Supplying it is not
// policy approval. This checker does not prove RBAC, admission, request
// authentication, source ownership, durable claiming or convergence.
type Constraints struct {
	Expected               Binding
	CommonName             string
	CADER                  []byte
	MaxValidity, ClockSkew time.Duration
}

func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(value[7:])
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}

func validBinding(b Binding) bool {
	for _, d := range []string{b.PlanDigest, b.PolicyDigest, b.Stage4ReceiptDigest, b.CADigest} {
		if !isDigest(d) {
			return false
		}
	}
	u, err := url.Parse(b.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.Opaque != "" {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	for _, s := range []string{b.Attempt, b.TargetUID, b.Endpoint, b.SourceNamespace, b.SourceName, b.SourceUID, b.SourceResourceVersion, b.SourceOwnerUID} {
		if strings.TrimSpace(s) != s || s == "" || len(s) > 2048 || !utf8.ValidString(s) {
			return false
		}
		for _, r := range s {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	// Privileged installer/probe profiles are deliberately not modeled yet.
	return b.SourceOwnerUID == b.TargetUID && (b.Role == "network-observer" || b.Role == "runtime-observer")
}

// SlotDigest identifies only the proposed coordination slot. It neither claims
// nor persists it. A different CSR/policy/source must not create another slot
// for the same plan, attempt, target and role; drift must be rejected separately.
func SlotDigest(b Binding) (string, error) {
	if !validBinding(b) {
		return "", errors.New("invalid bootstrap binding")
	}
	slot := struct{ Domain, Plan, Attempt, Target, Role string }{
		"ok147-bootstrap-slot-candidate", b.PlanDigest, b.Attempt, b.TargetUID, b.Role,
	}
	data, _ := json.Marshal(slot)
	return hash(data), nil
}

// RequestDigest binds the entire internal candidate request, including the CSR.
// No CLI or public JSON decoder accepts this experimental representation.
func RequestDigest(r Request) (string, error) {
	if !validBinding(r.Binding) || len(r.CSRDER) == 0 || len(r.CSRDER) > 16384 {
		return "", errors.New("invalid bootstrap request")
	}
	data, _ := json.Marshal(struct {
		Domain  string
		Request Request
	}{"ok147-bootstrap-request-candidate", r})
	return hash(data), nil
}

func exactSubject(raw []byte, commonName string) bool {
	want, err := asn1.Marshal((pkix.Name{CommonName: commonName}).ToRDNSequence())
	return err == nil && bytes.Equal(raw, want)
}

func validCommonName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name || strings.HasPrefix(name, "system:") || len(name) > 253 {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// ValidateRequest checks only local bytes against explicit independent inputs.
// It does not inspect any file, key source, network endpoint or live object.
func ValidateRequest(r Request, c Constraints) error {
	if !validBinding(c.Expected) || r.Binding != c.Expected {
		return errors.New("bootstrap binding differs from expected evidence")
	}
	if !validCommonName(c.CommonName) || c.MaxValidity <= 0 || c.ClockSkew < 0 || c.ClockSkew >= c.MaxValidity {
		return errors.New("explicit bootstrap subject and lifetime constraints required")
	}
	if _, err := RequestDigest(r); err != nil {
		return err
	}
	if len(c.CADER) == 0 || len(c.CADER) > 65536 || hash(c.CADER) != c.Expected.CADigest {
		return errors.New("bootstrap CA differs from expected evidence")
	}
	ca, err := x509.ParseCertificate(c.CADER)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid || ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("invalid bootstrap trust anchor")
	}
	csr, err := x509.ParseCertificateRequest(r.CSRDER)
	if err != nil || csr.CheckSignature() != nil || !exactSubject(csr.RawSubject, c.CommonName) || len(csr.Extensions) != 0 || len(csr.Attributes) != 0 {
		return errors.New("bootstrap CSR signature, subject or extensions rejected")
	}
	return nil
}

// ValidateResult proves certificate/request consistency only, not successful
// provisioning or permission to use the credential. The caller supplies time at
// initial result handoff; ClockSkew bounds initial certificate backdating, not a
// renewable lifetime. This is not a general reusable-certificate verifier.
func ValidateResult(r Request, result Result, c Constraints, now time.Time) error {
	return validateResultAt(r, result, c, now, true)
}

func validateResultAt(r Request, result Result, c Constraints, now time.Time, initial bool) error {
	if err := ValidateRequest(r, c); err != nil {
		return err
	}
	digest, _ := RequestDigest(r)
	if result.RequestDigest != digest || now.IsZero() || len(result.CertificateDER) == 0 || len(result.CertificateDER) > 65536 {
		return errors.New("bootstrap result is not bound to request and clock")
	}
	cert, err := x509.ParseCertificate(result.CertificateDER)
	if err != nil {
		return errors.New("invalid bootstrap certificate")
	}
	csr, _ := x509.ParseCertificateRequest(r.CSRDER)
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) || !exactSubject(cert.RawSubject, c.CommonName) {
		return errors.New("bootstrap certificate key or subject differs")
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 || len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 {
		return errors.New("bootstrap certificate capabilities rejected")
	}
	if !cert.NotAfter.After(cert.NotBefore) || cert.NotAfter.Sub(cert.NotBefore) > c.MaxValidity || cert.NotBefore.After(now) || (initial && now.Sub(cert.NotBefore) > c.ClockSkew) || !cert.NotAfter.After(now) {
		return errors.New("bootstrap certificate validity rejected")
	}
	ca, _ := x509.ParseCertificate(c.CADER)
	if cert.NotBefore.Before(ca.NotBefore) || cert.NotAfter.After(ca.NotAfter) || cert.CheckSignatureFrom(ca) != nil {
		return errors.New("bootstrap certificate issuer rejected")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("bootstrap certificate trust verification failed")
	}
	return nil
}
