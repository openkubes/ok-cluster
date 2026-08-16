package runner

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
	"strings"
	"testing"
	"time"
)

func TestOpenKubernetesLedgerValidatesProjectedInputs(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte("short-lived-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesLedger(KubernetesLedgerConfig{
		Endpoint: "https://10.43.0.1:443", Namespace: "openkubes-execution-system", TokenFile: tokenPath, CAFile: caPath,
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("token newline fails closed without path disclosure", func(t *testing.T) {
		if err := os.WriteFile(tokenPath, []byte("token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := OpenKubernetesLedger(KubernetesLedgerConfig{
			Endpoint: "https://10.43.0.1:443", Namespace: "openkubes-execution-system", TokenFile: tokenPath, CAFile: caPath,
		})
		if err == nil || strings.Contains(err.Error(), root) {
			t.Fatalf("unsafe token error: %v", err)
		}
	})

	t.Run("invalid CA fails closed without path disclosure", func(t *testing.T) {
		if err := os.WriteFile(tokenPath, []byte("short-lived-token"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(caPath, []byte("not-a-certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := OpenKubernetesLedger(KubernetesLedgerConfig{
			Endpoint: "https://10.43.0.1:443", Namespace: "openkubes-execution-system", TokenFile: tokenPath, CAFile: caPath,
		})
		if err == nil || strings.Contains(err.Error(), root) {
			t.Fatalf("unsafe CA error: %v", err)
		}
	})
}

func testCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ok147-test-ca"},
		NotBefore:             time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}
