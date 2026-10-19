package issuersourcecheck

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

const metadataFixture = `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":"fixture-ca","namespace":"fixture","uid":"source-uid","resourceVersion":"123","ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta1","kind":"Cluster","name":"fixture-cluster","uid":"target-uid","controller":true}]}}`

var ownerFixture = bootstrapcheck.SourceOwner{APIVersion: "cluster.x-k8s.io/v1beta1", Name: "fixture-cluster"}

func fixture(t *testing.T, key crypto.Signer, mutate func(*x509.Certificate)) ([]byte, []byte, bootstrapcheck.Binding) {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2000000000, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	expected := bootstrapcheck.Binding{PlanDigest: d, Attempt: "fixture-attempt", TargetUID: "target-uid",
		Endpoint: "https://192.0.2.10:6443", PolicyDigest: d, Stage4ReceiptDigest: d, Role: "network-observer",
		SourceNamespace: "fixture", SourceName: "fixture-ca", SourceUID: "source-uid", SourceResourceVersion: "123", SourceOwnerUID: "target-uid",
		CADigest: fmt.Sprintf("sha256:%x", sha256.Sum256(der))}
	return der, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), expected
}

func edKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestMatchingSourceKeysAndEncodings(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{rsaKey, ecKey, edKey(t)} {
		t.Run(fmt.Sprintf("%T", key), func(t *testing.T) {
			der, encoded, expected := fixture(t, key, nil)
			variants := [][]byte{encoded, append([]byte(" \n"), append(bytes.Clone(encoded), '\n')...)}
			switch k := key.(type) {
			case *rsa.PrivateKey:
				variants = append(variants, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
			case *ecdsa.PrivateKey:
				raw, err := x509.MarshalECPrivateKey(k)
				if err != nil {
					t.Fatal(err)
				}
				variants = append(variants, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}))
			}
			for _, value := range variants {
				before := bytes.Clone(value)
				if err := Validate([]byte(metadataFixture), der, value, expected, ownerFixture); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(value, before) {
					t.Fatal("mutated supplied key bytes")
				}
			}
		})
	}
}

func TestSourceKeyCorrespondenceRejectsInvalidOrAmbiguousMaterial(t *testing.T) {
	der, key, expected := fixture(t, edKey(t), nil)
	_, wrongKey, _ := fixture(t, edKey(t), nil)
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xRaw, err := x509.MarshalPKCS8PrivateKey(xKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(key)
	withDERJunk := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: append(bytes.Clone(block.Bytes), []byte("SENSITIVE_FIXTURE")...)})
	for name, value := range map[string][]byte{
		"trailing DER within PEM": withDERJunk,
		"empty":                   nil, "wrong key": wrongKey, "garbage": []byte("SENSITIVE_FIXTURE"),
		"too large": bytes.Repeat([]byte("x"), 16385), "trailing junk": append(bytes.Clone(key), []byte("SENSITIVE_FIXTURE")...),
		"leading junk": append([]byte("SENSITIVE_FIXTURE\n"), key...), "multiple keys": append(bytes.Clone(key), key...),
		"invalid first block":        append([]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n"), key...),
		"headers":                    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("SENSITIVE_FIXTURE")}),
		"encrypted type":             pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("SENSITIVE_FIXTURE")}),
		"certificate instead of key": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"malformed DER":              pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("SENSITIVE_FIXTURE")}),
		"malformed RSA":              pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("SENSITIVE_FIXTURE")}),
		"malformed EC":               pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("SENSITIVE_FIXTURE")}),
		"non-signing PKCS8":          pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: xRaw}),
	} {
		t.Run(name, func(t *testing.T) {
			err := Validate([]byte(metadataFixture), der, value, expected, ownerFixture)
			if err == nil || err.Error() != "issuer source identity or key correspondence rejected" {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestSourceMetadataAndCertificateCannotDrift(t *testing.T) {
	der, key, expected := fixture(t, edKey(t), nil)
	for name, metadata := range map[string]string{
		"UID":         strings.Replace(metadataFixture, "source-uid", "recreated", 1),
		"RV":          strings.Replace(metadataFixture, `"123"`, `"124"`, 1),
		"owner":       strings.Replace(metadataFixture, "target-uid", "other", 1),
		"full Secret": `{"apiVersion":"v1","kind":"Secret","data":{"tls.key":"SENSITIVE_FIXTURE"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if Validate([]byte(metadata), der, key, expected, ownerFixture) == nil {
				t.Fatal("accepted source drift")
			}
		})
	}
	for _, invalid := range [][]byte{nil, []byte("SENSITIVE_FIXTURE"), bytes.Repeat([]byte("x"), 65537)} {
		if Validate([]byte(metadataFixture), invalid, key, expected, ownerFixture) == nil {
			t.Fatal("accepted invalid certificate")
		}
		// Matching a caller-supplied digest cannot make malformed DER valid.
		bound := expected
		bound.CADigest = fmt.Sprintf("sha256:%x", sha256.Sum256(invalid))
		if Validate([]byte(metadataFixture), invalid, key, bound, ownerFixture) == nil {
			t.Fatal("accepted malformed DER with a matching digest")
		}
	}
	wrongFingerprint := expected
	wrongFingerprint.CADigest = "sha256:" + strings.Repeat("b", 64)
	if Validate([]byte(metadataFixture), der, key, wrongFingerprint, ownerFixture) == nil {
		t.Fatal("accepted a different independently expected CA fingerprint")
	}
	for _, change := range []func(*x509.Certificate){
		func(c *x509.Certificate) { c.IsCA = false },
		func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature },
	} {
		badDER, badKey, bound := fixture(t, edKey(t), change)
		if Validate([]byte(metadataFixture), badDER, badKey, bound, ownerFixture) == nil {
			t.Fatal("accepted non-CA/non-signing certificate")
		}
	}
	if Validate([]byte(metadataFixture), der, key, bootstrapcheck.Binding{}, ownerFixture) == nil {
		t.Fatal("accepted missing expectations")
	}
	if Validate([]byte(metadataFixture), der, key, expected, bootstrapcheck.SourceOwner{}) == nil {
		t.Fatal("accepted missing owner")
	}
	privileged := expected
	privileged.Role = "target-access"
	if Validate([]byte(metadataFixture), der, key, privileged, ownerFixture) == nil {
		t.Fatal("broadened the existing observer-only candidate binding")
	}
}

func TestKeyCorrespondenceIsNotIssuanceOrFreshnessApproval(t *testing.T) {
	// This counterexample makes the helper's limit explicit. Matching source
	// bytes and a usable key do not replace the issuer's time/profile checks.
	// This is not a requirement to keep accepting expired CAs: replace the
	// example when a separately reviewed issuance-time contract adds time checks.
	der, key, expected := fixture(t, edKey(t), func(c *x509.Certificate) { c.NotAfter = time.Unix(100, 0) })
	if err := Validate([]byte(metadataFixture), der, key, expected, ownerFixture); err != nil {
		t.Fatalf("correspondence helper unexpectedly became an issuance-time policy: %v", err)
	}
}
