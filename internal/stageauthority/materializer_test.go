package stageauthority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMaterializeCopiesExactProjectedSetPrivately(t *testing.T) {
	config := materializationFixture(t)
	receipt, err := Materialize(config)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "WRITTEN_VERIFIED" || receipt.PolicyDigest != config.ExpectedPolicyDigest ||
		receipt.KeyID != config.ExpectedKeyID || receipt.TLSIdentityDigest == "" || receipt.FileCount != 5 || receipt.FileMode != "0600" || receipt.MutationAllowed {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	for _, expected := range materializedFiles {
		info, err := os.Lstat(filepath.Join(config.DestinationDirectory, expected.name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("private file %s differs: %#v %v", expected.name, info, err)
		}
	}
	stopped, err := Materialize(config)
	if err == nil || stopped.State != "PREWRITE" {
		t.Fatalf("non-empty destination was accepted: %#v %v", stopped, err)
	}
}

func TestMaterializeRejectsEscapingProjectionBeforeWrite(t *testing.T) {
	config := materializationFixture(t)
	outside := filepath.Join(t.TempDir(), "outside-token")
	if err := os.WriteFile(outside, []byte("foreign-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(config.SourceDirectory, "client-token")
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, tokenPath); err != nil {
		t.Fatal(err)
	}
	receipt, err := Materialize(config)
	if err == nil || receipt.State != "PREWRITE" {
		t.Fatalf("escaping projection was accepted: %#v %v", receipt, err)
	}
	entries, readErr := os.ReadDir(config.DestinationDirectory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("rejected projection wrote files: %d %v", len(entries), readErr)
	}
}

func materializationFixture(t *testing.T) MaterializationConfig {
	t.Helper()
	material := testMaterial(t)
	source := filepath.Join(t.TempDir(), "source")
	data := filepath.Join(source, "data")
	destination := filepath.Join(t.TempDir(), "private")
	state := filepath.Join(t.TempDir(), "claims")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(material.config.PolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, err := os.ReadFile(material.config.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	certRaw, keyRaw := selfSignedTLS(t)
	values := map[string][]byte{
		"policy.json": policyRaw, "authority.key": privateRaw, "client-token": []byte(material.token),
		"tls.crt": certRaw, "tls.key": keyRaw,
	}
	for name, raw := range values {
		if err := os.WriteFile(filepath.Join(data, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("data", name), filepath.Join(source, name)); err != nil {
			t.Fatal(err)
		}
	}
	return MaterializationConfig{
		SourceDirectory: source, DestinationDirectory: destination, StateDirectory: state,
		ExpectedPolicyDigest: material.config.ExpectedPolicyDigest, ExpectedKeyID: digestBytes(material.publicKey),
	}
}

func selfSignedTLS(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ok147-stage-authority"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"ok147-stage-authority"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
