package kubeconfigtarget

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func certificate(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline test CA"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func fixture(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	ca := certificate(t)
	raw := []byte("apiVersion: v1\nkind: Config\ncurrent-context: not-selected\ncontexts:\n- name: only\n  context: {cluster: target, user: identity}\nclusters:\n- name: target\n  cluster:\n    server: https://MGMT.example:443/\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(ca) + "\nusers:\n- name: identity\n  user:\n    token: SUPER_SECRET_DO_NOT_LOG\n    exec: {command: must-never-run, apiVersion: client.authentication.k8s.io/v1}\n")
	path := filepath.Join(t.TempDir(), "private.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, raw, ca
}

func TestTargetSelectionIsUniqueReadOnlyAndCredentialFree(t *testing.T) {
	path, before, ca := fixture(t)
	selected, err := Read(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Context != "only" || selected.Endpoint != "https://mgmt.example" {
		t.Fatalf("wrong target: %+v", selected)
	}
	if err := selected.MatchTransport("https://mgmt.example/", ca); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("kubeconfig changed")
	}
	if _, err := ReadCurrent(path); err == nil {
		t.Fatal("invalid provider current context accepted")
	}
	other := bytes.Replace(before, []byte("contexts:\n"), []byte("contexts:\n- name: another\n  context: {cluster: target, user: identity}\n"), 1)
	other = bytes.Replace(other, []byte("current-context: not-selected"), []byte("current-context: another"), 1)
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, ""); err == nil {
		t.Fatal("followed current-context in multi-context file")
	}
	if _, err := Read(path, "only"); err != nil {
		t.Fatal(err)
	}
	if chosen, err := ReadCurrent(path); err != nil || chosen.Context != "another" {
		t.Fatalf("provider selection: %+v %v", chosen, err)
	}
	if _, err := Read(path, "missing"); err == nil {
		t.Fatal("missing explicit context accepted")
	}
}

func TestTargetReaderRejectsAmbiguityUnsafeTransportAndLeaks(t *testing.T) {
	for name, change := range map[string]func([]byte) []byte{
		"duplicate-key": func(raw []byte) []byte { return append(raw, []byte("kind: Config\n")...) },
		"duplicate-name": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("contexts:\n"), []byte("contexts:\n- name: only\n  context: {cluster: target, user: identity}\n"), 1)
		},
		"alias":    func(raw []byte) []byte { return bytes.Replace(raw, []byte("name: only"), []byte("name: &ref only"), 1) },
		"trailing": func(raw []byte) []byte { return append(raw, []byte("---\nsecret: SUPER_SECRET_DO_NOT_LOG\n")...) },
		"http":     func(raw []byte) []byte { return bytes.ReplaceAll(raw, []byte("https://"), []byte("http://")) },
		"insecure": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("    server:"), []byte("    insecure-skip-tls-verify: true\n    server:"), 1)
		},
		"proxy": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("    server:"), []byte("    proxy-url: https://proxy\n    server:"), 1)
		},
		"tls-override": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte("    server:"), []byte("    tls-server-name: foreign\n    server:"), 1)
		},
		"missing-user": func(raw []byte) []byte {
			return bytes.ReplaceAll(raw, []byte("user: identity"), []byte("user: missing"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, raw, _ := fixture(t)
			if err := os.WriteFile(path, change(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Read(path, "")
			if err == nil || strings.Contains(err.Error(), "SUPER_SECRET") {
				t.Fatalf("unsafe result: %v", err)
			}
		})
	}
	path, _, _ := fixture(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, ""); err == nil {
		t.Fatal("public credential file accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := Read(link, ""); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestTargetCAFilesAreRelativeAndTrustComparisonIsSemantic(t *testing.T) {
	path, raw, ca := fixture(t)
	caPath := filepath.Join(filepath.Dir(path), "ca.pem")
	if err := os.WriteFile(caPath, ca, 0o644); err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(raw, []byte("    certificate-authority-data:"))
	end := bytes.Index(raw[start:], []byte("\n")) + start
	raw = append(append(append([]byte{}, raw[:start]...), []byte("    certificate-authority: ca.pem")...), raw[end:]...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := Read(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := target.MatchTransport("https://mgmt.example", append([]byte("\n"), append(ca, ca...)...)); err != nil {
		t.Fatal(err)
	}
	if err := target.MatchTransport("https://other.example", ca); err == nil {
		t.Fatal("wrong endpoint accepted")
	}
	if err := target.MatchTransport("https://mgmt.example", certificate(t)); err == nil {
		t.Fatal("wrong CA accepted")
	}
	if _, err := TrustDigest(append(ca, []byte("extra junk")...)); err == nil {
		t.Fatal("trailing CA junk accepted")
	}
}
