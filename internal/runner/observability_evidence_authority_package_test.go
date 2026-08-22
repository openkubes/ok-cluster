package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildObservabilityEvidenceAuthorityPackageBindsPrivateAuthority(t *testing.T) {
	config, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	defer cleanup()
	packaged, err := BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != ObservabilityEvidenceAuthorityPackageFormat || receipt.State != "VERIFIED" ||
		receipt.ActivationSecret != config.ActivationSecret || receipt.PrivateFileCount != 4 ||
		len(receipt.ObjectKinds) != 1 || receipt.ObjectKinds[0] != "Secret" || receipt.MutationAllowed {
		t.Fatalf("unexpected evidence authority package receipt: %#v", receipt)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"independent-evidence-token", config.CollectorEndpoint, config.PrivateKeyPath, "BEGIN CERTIFICATE"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("evidence authority receipt disclosed %q: %s", forbidden, public)
		}
	}
	raw, err := packaged.PrivateBytes()
	if err != nil || digest.SHA256(raw) != receipt.PackageDigest {
		t.Fatalf("private evidence authority package identity differs: %v", err)
	}
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(raw, &secret); err != nil {
		t.Fatal(err)
	}
	if secret.Kind != "Secret" || !secret.Immutable || secret.Metadata.Namespace != submissionStageInputNamespace ||
		secret.Metadata.Name != config.ActivationSecret || len(secret.Data) != 4 {
		t.Fatalf("unexpected evidence authority Secret: %#v", secret)
	}
	activationRaw, err := base64.StdEncoding.DecodeString(secret.Data[observabilityEvidenceAuthorityActivationKey])
	if err != nil {
		t.Fatal(err)
	}
	var activation ObservabilityEvidenceAuthorityActivation
	if err := json.Unmarshal(activationRaw, &activation); err != nil {
		t.Fatal(err)
	}
	if activation.Format != ObservabilityEvidenceAuthorityActivationFormat || activation.State != "BOUND" ||
		activation.ExpectedManifestDigest != receipt.ManifestDigest ||
		activation.IdentityPath != observabilityEvidenceAuthorityHandoffRoot+"/observability-evidence-identity.json" ||
		activation.IdentityReceiptPath != observabilityEvidenceAuthorityHandoffRoot+"/observability-evidence-identity-receipt.json" ||
		activation.EvidenceOutputPath != observabilityEvidenceAuthorityHandoffRoot+"/observability-evidence.json" ||
		activation.PrivateKeyPath != observabilityEvidenceAuthorityRoot+"/"+observabilityEvidenceAuthorityPrivateKeyKey ||
		activation.CollectorEndpoint != config.CollectorEndpoint || activation.IdentityWaitTimeout != "30m0s" {
		t.Fatalf("evidence authority activation differs: %#v", activation)
	}
	privateKey, _ := base64.StdEncoding.DecodeString(secret.Data[observabilityEvidenceAuthorityPrivateKeyKey])
	token, _ := base64.StdEncoding.DecodeString(secret.Data[observabilityEvidenceAuthorityCollectorToken])
	ca, _ := base64.StdEncoding.DecodeString(secret.Data[observabilityEvidenceAuthorityCollectorCA])
	if len(privateKey) == 0 || string(token) != "independent-evidence-token" || digest.SHA256(ca) != receipt.CollectorCADigest {
		t.Fatal("private evidence authority material differs from verified sources")
	}
}

func TestBuildObservabilityEvidenceAuthorityPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *ObservabilityEvidenceAuthorityPackageConfig){
		"foreign Secret": func(_ *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			config.ActivationSecret = "foreign-secret"
		},
		"foreign key": func(t *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			_, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "foreign.key")
			if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config.PrivateKeyPath = path
		},
		"exposed collector credential": func(t *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			if err := os.Chmod(config.CollectorTokenPath, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"foreign CA": func(_ *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			config.CollectorCADigest = bundleSHA("f")
		},
		"insecure endpoint": func(_ *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			config.CollectorEndpoint = "http://192.0.2.50:8443"
		},
		"unbounded wait": func(_ *testing.T, config *ObservabilityEvidenceAuthorityPackageConfig) {
			config.IdentityWaitTimeout = 4 * time.Hour
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
			defer cleanup()
			mutate(t, &config)
			if _, err := BuildObservabilityEvidenceAuthorityPackage(config); err == nil {
				t.Fatal("unsafe evidence authority package was accepted")
			}
		})
	}
}

func TestObservabilityEvidenceAuthorityPackageRejectsTampering(t *testing.T) {
	config, cleanup := observabilityEvidenceAuthorityPackageFixture(t)
	defer cleanup()
	packaged, err := BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.raw[0] ^= 0xff
	if _, err := packaged.PrivateBytes(); err == nil {
		t.Fatal("tampered evidence authority package was accepted")
	}
	packaged, err = BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.receipt.ObjectKinds[0] = "ConfigMap"
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("tampered evidence authority inventory was accepted")
	}
	packaged, err = BuildObservabilityEvidenceAuthorityPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.receipt.CollectorCADigest = bundleSHA("a")
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("tampered evidence authority CA identity was accepted")
	}
}

func observabilityEvidenceAuthorityPackageFixture(t *testing.T) (ObservabilityEvidenceAuthorityPackageConfig, func()) {
	t.Helper()
	manifestPath, manifestCleanup := fullRunExecutionManifestFixture(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := digest.SHA256(publicKey)
	bindFullRunEvidenceKeyID(t, manifestPath, keyID)
	root := t.TempDir()
	privateKeyPath := filepath.Join(root, "evidence-authority.key")
	tokenPath := filepath.Join(root, "collector-token")
	caPath := filepath.Join(root, "collector-ca.crt")
	if err := os.WriteFile(privateKeyPath, []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("independent-evidence-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var collection ObservabilityIndependentEvidenceCollectionRequest
		if err := json.Unmarshal(raw, &collection); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		_, requestDigest, err := canonicalObservabilityIndependentEvidenceCollectionRequest(collection)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(ObservabilityIndependentEvidenceCollectionResponse{
			Format: ObservabilityIndependentEvidenceCollectionResponseFormat, RequestDigest: requestDigest,
			ReceiverDeliveryObserved: true, ReceiverIdentityDigest: digest.SHA256([]byte("receiver")),
			ClusterLocalServicesReady: true, ExternalClusterDependencies: 0,
			AutonomyProfileDigest: digest.SHA256([]byte("autonomy")),
		})
	}))
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		server.Close()
		t.Fatal(err)
	}
	return ObservabilityEvidenceAuthorityPackageConfig{
			ManifestPath: manifestPath, ActivationSecret: "ok147-observability-evidence-authority-01",
			PrivateKeyPath: privateKeyPath, CollectorEndpoint: server.URL,
			CollectorTokenPath: tokenPath, CollectorCAPath: caPath, CollectorCADigest: digest.SHA256(ca),
			RuntimeAuthorityRoot: observabilityEvidenceAuthorityRoot, RuntimeHandoffRoot: observabilityEvidenceAuthorityHandoffRoot,
			IdentityPollInterval: time.Second, IdentityWaitTimeout: 30 * time.Minute,
			EvidenceValidFor: 10 * time.Minute, CollectionTimeout: 2 * time.Minute,
		}, func() {
			server.Close()
			manifestCleanup()
		}
}
