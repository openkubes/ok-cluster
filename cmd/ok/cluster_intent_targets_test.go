package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestClusterIntentRejectsTargetDriftBeforeManifestCredentialGate(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, role := range []string{"management", "infrastructure"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			config := "apiVersion: v1\nkind: Config\ncontexts:\n- name: selected\n  context: {cluster: target, user: identity}\nclusters:\n- name: target\n  cluster:\n    server: https://192.0.2.10:6443\n    certificate-authority-data: " + trust + "\nusers:\n- name: identity\n  user:\n    exec: {command: must-never-run}\n"
			for _, name := range []string{"management", "infrastructure"} {
				if err := os.WriteFile(filepath.Join(root, name+".yaml"), []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := intentFixture(t, func(raw string) string {
				return strings.Replace(raw, "  profile:", "  management: {kubeconfig: "+filepath.Join(root, "management.yaml")+"}\n  infrastructure: {kubeconfig: "+filepath.Join(root, "infrastructure.yaml")+"}\n  profile:", 1)
			})
			intent, err := readClusterIntent(path)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := readClusterIntentTargets(path, intent)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(intent)
			if err != nil {
				t.Fatal(err)
			}
			binding := clusterIntentBindingReceipt{NormalizedIntentDigest: digest.SHA256(raw), Targets: targets}
			// Change only the referenced kubeconfig, not YAML or its digest.
			if err := os.WriteFile(filepath.Join(root, role+".yaml"), []byte(strings.Replace(config, "192.0.2.10", "192.0.2.11", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			// An absent manifest ensures a loader failure cannot masquerade as
			// successful coverage of the exact target-drift branch.
			err = verifyClusterIntentTargets(path, binding, filepath.Join(root, "absent-manifest"), "")
			if err == nil || err.Error() != "selected kubeconfig target changed since preparation; no execution" {
				t.Fatalf("target drift was shadowed: %v", err)
			}
		})
	}
}

func TestClusterIntentTargetReferencesArePairedAndStrict(t *testing.T) {
	for _, fields := range []string{
		"  management: {kubeconfig: ~/.kube/mgmt}\n",
		"  management: {kubeconfig: ''}\n  infrastructure: {kubeconfig: infra}\n",
		"  management: {kubeconfig: mgmt, currentContext: accidental}\n  infrastructure: {kubeconfig: infra}\n",
		"  management: {kubeconfig: mgmt, context: 123}\n  infrastructure: {kubeconfig: infra}\n",
	} {
		path := intentFixture(t, func(raw string) string { return strings.Replace(raw, "  profile:", fields+"  profile:", 1) })
		if _, err := readClusterIntent(path); err == nil {
			t.Fatal("ambiguous reference schema accepted")
		}
	}
	path := intentFixture(t, func(raw string) string {
		return strings.Replace(raw, "  profile:", "  management: {kubeconfig: ~/.kube/mgmt}\n  infrastructure: {kubeconfig: relative/infra, context: chosen}\n  profile:", 1)
	})
	intent, err := readClusterIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Spec.Infrastructure.Context != "chosen" {
		t.Fatal("lost explicit context")
	}
}

func TestClusterIntentWithoutReferencesKeepsNormalizedIdentity(t *testing.T) {
	intent, err := readClusterIntent(intentFixture(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"apiVersion":"cli.openkubes.io/v1alpha1","kind":"Cluster","metadata":{"name":"my-cluster"},"spec":{"profile":"talos-kubevirt-mvp","network":{"endpoint":"192.0.2.10","podCIDR":"10.42.0.0/16","serviceCIDR":"10.96.0.0/20"}}}`
	if string(raw) != expected {
		t.Fatalf("changed legacy intent identity: %s", raw)
	}
	binding, _ := json.Marshal(clusterIntentBindingReceipt{})
	if strings.Contains(string(binding), `"targets"`) {
		t.Fatal("nil targets changed old binding receipt shape")
	}
}
