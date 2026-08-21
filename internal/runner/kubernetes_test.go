package runner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
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

func TestOpenKubernetesSubmissionClientBindsOneAuthority(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte("short-lived-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesSubmissionClient(KubernetesAuthorityConfig{
		Endpoint:          "https://10.43.0.1:443",
		AuthorityIdentity: "ok-mgmt",
		TokenFile:         tokenPath,
		CAFile:            caPath,
	}); err != nil {
		t.Fatal(err)
	}

	for name, config := range map[string]KubernetesAuthorityConfig{
		"missing identity": {
			Endpoint: "https://10.43.0.1:443", TokenFile: tokenPath, CAFile: caPath,
		},
		"invalid identity": {
			Endpoint: "https://10.43.0.1:443", AuthorityIdentity: "ok.mgmt", TokenFile: tokenPath, CAFile: caPath,
		},
		"endpoint path": {
			Endpoint: "https://10.43.0.1:443/api", AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, CAFile: caPath,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenKubernetesSubmissionClient(config); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe authority config accepted or disclosed a path: %v", err)
			}
		})
	}
}

func TestOpenKubernetesSubmissionClientAcceptsStrictClientCertificateKubeconfig(t *testing.T) {
	root := t.TempDir()
	ca, certificate, key := testClientCredential(t)
	caPath := filepath.Join(root, "workload-ca.crt")
	kubeconfigPath := filepath.Join(root, "workload.kubeconfig")
	endpoint := "https://192.0.2.90:6443"
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kubeconfigPath, testClientKubeconfig(endpoint, ca, certificate, key), 0o600); err != nil {
		t.Fatal(err)
	}
	config := KubernetesAuthorityConfig{
		Endpoint: endpoint, AuthorityIdentity: "cluster-uid-disposable-ok147",
		KubeconfigFile: kubeconfigPath, CAFile: caPath,
	}
	if _, identity, err := openKubernetesSubmissionClient(config); err != nil || !stageReceiptPrefixDigestPattern.MatchString(identity) {
		t.Fatalf("strict client-certificate kubeconfig was not accepted: identity=%q err=%v", identity, err)
	}

	t.Run("token and kubeconfig fail closed", func(t *testing.T) {
		candidate := config
		candidate.TokenFile = kubeconfigPath
		if _, err := OpenKubernetesSubmissionClient(candidate); err == nil || strings.Contains(err.Error(), root) {
			t.Fatalf("ambiguous workload credential accepted or disclosed path: %v", err)
		}
	})

	t.Run("different separately bound CA fails closed", func(t *testing.T) {
		foreignCA := filepath.Join(root, "foreign-ca.crt")
		if err := os.WriteFile(foreignCA, testCA(t), 0o600); err != nil {
			t.Fatal(err)
		}
		candidate := config
		candidate.CAFile = foreignCA
		if _, err := OpenKubernetesSubmissionClient(candidate); err == nil || strings.Contains(err.Error(), root) {
			t.Fatalf("foreign workload CA accepted or disclosed path: %v", err)
		}
	})
}

func TestOpenKubernetesCAPILifecycleObserverBindsManagementAuthority(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte("short-lived-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, testCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	config := KubernetesAuthorityConfig{
		Endpoint: "https://10.43.0.1:443", AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, CAFile: caPath,
	}
	if _, err := OpenKubernetesCAPILifecycleObserver(config, "ok-mgmt", "disposable-ok141", "disposable-ok141"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKubernetesCAPILifecycleObserver(config, "different", "disposable-ok141", "disposable-ok141"); err == nil {
		t.Fatal("mismatched management authority accepted")
	}
	if _, err := OpenKubernetesCAPILifecycleObserver(config, "ok-mgmt", "INVALID", "disposable-ok141"); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("unsafe target identity accepted or disclosed a path: %v", err)
	}
}

func TestOpenKubernetesNetworkSourceCollectorBindsDistinctAuthorities(t *testing.T) {
	root := t.TempDir()
	managementToken := filepath.Join(root, "management-token")
	workloadToken := filepath.Join(root, "workload-token")
	caPath := filepath.Join(root, "ca.crt")
	ca := testCA(t)
	for path, value := range map[string][]byte{
		managementToken: []byte("short-lived-management-token"),
		workloadToken:   []byte("short-lived-workload-token"),
		caPath:          ca,
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	targetUID := "cluster-uid-disposable-ok141"
	base := KubernetesNetworkObserverConfig{
		Management: KubernetesAuthorityConfig{
			Endpoint: "https://10.43.0.1:443", AuthorityIdentity: "ok-mgmt", TokenFile: managementToken, CAFile: caPath,
		},
		Workload: KubernetesAuthorityConfig{
			Endpoint: "https://192.168.100.213:6443", AuthorityIdentity: targetUID, TokenFile: workloadToken, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		},
		ExpectedManagementAuthority: "ok-mgmt", TargetClusterUID: targetUID,
		Namespace: "disposable-ok141", Name: "disposable-ok141", HCPName: "disposable-ok141-cilium",
		Clock: func() time.Time { return time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC) },
	}
	if _, err := OpenKubernetesNetworkSourceCollector(base); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*KubernetesNetworkObserverConfig){
		"management authority": func(config *KubernetesNetworkObserverConfig) {
			config.ExpectedManagementAuthority = "other"
		},
		"workload authority": func(config *KubernetesNetworkObserverConfig) {
			config.Workload.AuthorityIdentity = "other-uid"
		},
		"shared endpoint": func(config *KubernetesNetworkObserverConfig) {
			config.Workload.Endpoint = config.Management.Endpoint
		},
		"shared credential": func(config *KubernetesNetworkObserverConfig) {
			config.Workload.TokenFile = config.Management.TokenFile
		},
		"missing workload CA binding": func(config *KubernetesNetworkObserverConfig) {
			config.Workload.CABundleDigest = ""
		},
		"different workload CA binding": func(config *KubernetesNetworkObserverConfig) {
			config.Workload.CABundleDigest = "sha256:" + strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if _, err := OpenKubernetesNetworkSourceCollector(candidate); err == nil || strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe network authority configuration accepted or disclosed a path: %v", err)
			}
		})
	}
}

func TestOpenKubernetesPlatformSourceCollectorBindsGitOpsAuthority(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "token")
	caPath := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(tokenPath, []byte("short-lived-platform-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := testCA(t)
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	digestOf := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	profile := observation.PlatformProfile{
		Format: observation.PlatformProfileFormat, IntentRevision: digestOf("a"), PlatformRevision: digestOf("b"), ExecutionFixture: digestOf("c"),
		TargetIdentityScheme: "capi-cluster-uid/v1", ArgoNamespace: "argocd", RegistrationName: "disposable-ok141",
		RequiredApplications:     []observation.PlatformApplicationExpectation{{Name: "disposable-ok141-observability-core", SpecDigest: digestOf("d")}},
		CapabilityContractDigest: digestOf("e"), CapabilityExecutableDigest: digestOf("f"), MaximumCapabilityAgeSeconds: 3600,
	}
	config := KubernetesPlatformObserverConfig{
		Argo: KubernetesAuthorityConfig{
			Endpoint: "https://10.43.0.1:443", AuthorityIdentity: "ok-shared", TokenFile: tokenPath, CAFile: caPath, CABundleDigest: digest.SHA256(ca),
		},
		ExpectedArgoAuthority: "ok-shared", Profile: profile, Capability: inertPlatformCapabilitySource{}, TargetClusterUID: "cluster-uid-disposable-ok141", Clock: time.Now,
	}
	if _, err := OpenKubernetesPlatformSourceCollector(config); err != nil {
		t.Fatal(err)
	}
	config.ExpectedArgoAuthority = "other"
	if _, err := OpenKubernetesPlatformSourceCollector(config); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("unsafe GitOps authority accepted or disclosed a path: %v", err)
	}
}

type inertPlatformCapabilitySource struct{}

func (inertPlatformCapabilitySource) Capability(context.Context) (observation.PlatformCapabilityState, error) {
	return observation.PlatformCapabilityState{}, nil
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

func testClientCredential(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "ok147-workload-test-ca"},
		NotBefore: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "ok147-workload-client"},
		NotBefore: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func testClientKubeconfig(endpoint string, ca, certificate, key []byte) []byte {
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: workload
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: workload
  context:
    cluster: workload
    user: workload
current-context: workload
preferences: {}
users:
- name: workload
  user:
    client-certificate-data: %s
    client-key-data: %s
`, endpoint, base64.StdEncoding.EncodeToString(ca), base64.StdEncoding.EncodeToString(certificate), base64.StdEncoding.EncodeToString(key)))
}
