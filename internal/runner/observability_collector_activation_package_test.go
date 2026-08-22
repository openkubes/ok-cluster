package runner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestBuildObservabilityCollectorActivationPackageBindsPrivateRuntime(t *testing.T) {
	config, cleanup := observabilityCollectorActivationFixture(t)
	defer cleanup()
	packaged, err := BuildObservabilityCollectorActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, err := packaged.PrivateBytes()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != ObservabilityCollectorActivationPackageFormat || receipt.State != "VERIFIED" ||
		receipt.PackageDigest != digest.SHA256(privateRaw) || receipt.PrivateFileCount != 7 ||
		receipt.PublicEndpointDigest != digest.SHA256([]byte(config.PublicEndpoint)) ||
		receipt.MutationAllowed || len(receipt.ObjectKinds) != 1 || receipt.ObjectKinds[0] != "Secret" {
		t.Fatalf("unexpected collector activation receipt: %#v", receipt)
	}
	var secret postRuntimeActivationSecret
	if err := json.Unmarshal(privateRaw, &secret); err != nil {
		t.Fatal(err)
	}
	if !secret.Immutable || secret.Metadata.Name != config.ActivationSecret || len(secret.Data) != 7 {
		t.Fatalf("unexpected collector activation Secret: %#v", secret.Metadata)
	}
	activationRaw, err := base64.StdEncoding.DecodeString(secret.Data[observabilityCollectorActivationKey])
	if err != nil {
		t.Fatal(err)
	}
	var activation ObservabilityCollectorActivation
	if err := json.Unmarshal(activationRaw, &activation); err != nil {
		t.Fatal(err)
	}
	if activation.State != "BOUND" || activation.PublicEndpoint != config.PublicEndpoint ||
		activation.ManifestReceiptDigest != config.ExpectedReceiptDigest ||
		activation.ReceiverName != observabilityCollectorReceiver ||
		activation.TargetClusterUID == "" || activation.WorkloadEndpoint == "" ||
		digest.SHA256([]byte(activation.TargetClusterUID)) != receipt.TargetClusterUIDDigest {
		t.Fatalf("collector activation lost runtime identity: %#v", activation)
	}
	publicRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, privateValue := range []string{
		activation.TargetClusterUID, activation.WorkloadEndpoint,
		string(mustDecodeCollectorSecret(t, secret, observabilityCollectorWebhookKey)),
		string(mustDecodeCollectorSecret(t, secret, observabilityCollectorQueryKey)),
		string(mustDecodeCollectorSecret(t, secret, observabilityCollectorWorkloadKey)),
	} {
		if bytes.Contains(publicRaw, []byte(privateValue)) {
			t.Fatal("collector activation receipt disclosed private runtime material")
		}
	}
	privateRaw[0] = 'x'
	again, err := packaged.PrivateBytes()
	if err != nil || again[0] != '{' {
		t.Fatal("caller mutated retained collector activation package")
	}
	receipt.ObjectKinds[0] = "Changed"
	againReceipt, err := packaged.Receipt()
	if err != nil || againReceipt.ObjectKinds[0] != "Secret" {
		t.Fatal("caller mutated retained collector activation receipt")
	}
}

func TestBuildObservabilityCollectorActivationPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*ObservabilityCollectorActivationPackageConfig){
		"foreign manifest": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.ExpectedManifestDigest = runnerStageSHA("f")
		},
		"foreign manifest receipt": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.ExpectedReceiptDigest = runnerStageSHA("f")
		},
		"foreign runtime path": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.RuntimeBinding.MaterialPath = filepath.Join(t.TempDir(), "runtime.json")
		},
		"foreign observer": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.ObserverCredential.ExpectedSubject = "system:serviceaccount:ok-observability:other"
		},
		"shared authorities": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.QueryTokenPath = config.WebhookTokenPath
		},
		"wrong endpoint": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.PublicEndpoint = "https://192.0.2.45:8443"
		},
		"broad listen mismatch": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.ListenAddress = "0.0.0.0:9443"
		},
		"stale observer": func(config *ObservabilityCollectorActivationPackageConfig) {
			config.MaterializationTime = config.ObserverCredential.ExpiresAt.Add(-10 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, cleanup := observabilityCollectorActivationFixture(t)
			defer cleanup()
			mutate(&config)
			if _, err := BuildObservabilityCollectorActivationPackage(config); err == nil {
				t.Fatal("unsafe collector activation package was accepted")
			}
		})
	}
	if _, err := (VerifiedObservabilityCollectorActivationPackage{}).PrivateBytes(); err == nil {
		t.Fatal("unverified collector activation bytes were exposed")
	}
	if _, err := (VerifiedObservabilityCollectorActivationPackage{}).Receipt(); err == nil {
		t.Fatal("unverified collector activation receipt was exposed")
	}
}

func TestBuildObservabilityCollectorActivationPackageAcceptsOnlyBoundInMemoryObserverToken(t *testing.T) {
	config, cleanup := observabilityCollectorActivationFixture(t)
	defer cleanup()
	token, err := os.ReadFile(config.ObserverCredential.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	config.ObserverCredential.TokenFile = ""
	config.ObserverToken = token
	packaged, err := BuildObservabilityCollectorActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil || receipt.ObserverTokenRequestEvidence != config.ObserverCredential.TokenRequestEvidenceDigest {
		t.Fatalf("in-memory observer credential was not bound: %#v %v", receipt, err)
	}
	config.ObserverToken = append([]byte(nil), token...)
	config.ObserverToken[len(config.ObserverToken)-1] ^= 1
	if packaged, err := BuildObservabilityCollectorActivationPackage(config); err == nil || packaged.verified {
		t.Fatal("changed in-memory observer credential was accepted")
	}
}

func TestBuildObservabilityCollectorActivationPackageAcceptsVerifiedManifestReceiptInMemory(t *testing.T) {
	config, cleanup := observabilityCollectorActivationFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(config.ManifestReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt FullRunExecutionManifestReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	config.ManifestReceiptPath = ""
	config.ManifestReceipt = &receipt
	if packaged, err := BuildObservabilityCollectorActivationPackage(config); err != nil || !packaged.verified {
		t.Fatalf("verified in-memory manifest receipt was rejected: %v", err)
	}
	receipt.ManifestDigest = runnerStageSHA("f")
	if packaged, err := BuildObservabilityCollectorActivationPackage(config); err == nil || packaged.verified {
		t.Fatal("changed in-memory manifest receipt was accepted")
	}
}

func observabilityCollectorActivationFixture(t *testing.T) (ObservabilityCollectorActivationPackageConfig, func()) {
	t.Helper()
	manifestPath, cleanup := fullRunExecutionManifestFixture(t)
	manifest, manifestReceipt, err := LoadFullRunExecutionManifest(manifestPath)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	manifestReceiptRaw, err := json.Marshal(manifestReceipt)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	manifestReceiptPath := writeBundleFile(t, t.TempDir(), "full-run-manifest-receipt.json", manifestReceiptRaw)
	ca := collectorTestCA(t, at)
	runtime := collectorRuntimeBindingFiles(t, manifest, ca, at)
	root := t.TempDir()
	issuedAt, expiresAt := at.Add(-time.Minute), at.Add(45*time.Minute)
	subject := "system:serviceaccount:ok-observability:" + observabilityCollectorObserverSA
	token := stageCredentialJWT(t, "https://kubernetes.default.svc.cluster.local", subject, []string{"https://kubernetes.default.svc"}, issuedAt, expiresAt, 'z')
	tokenPath := writeBundleFile(t, root, "observer-token", token)
	caPath := writeBundleFile(t, root, "workload-ca.crt", ca)
	webhookPath := writeBundleFile(t, root, "webhook-token", []byte(strings.Repeat("w", 48)))
	queryPath := writeBundleFile(t, root, "query-token", []byte(strings.Repeat("q", 48)))
	certificate, privateKey := collectorServerCredential(t, at, net.ParseIP("192.0.2.44"))
	certificatePath := writeBundleFile(t, root, "tls.crt", certificate)
	privateKeyPath := writeBundleFile(t, root, "tls.key", privateKey)
	return ObservabilityCollectorActivationPackageConfig{
		ManifestPath: manifestPath, ExpectedManifestDigest: manifestReceipt.ManifestDigest,
		ManifestReceiptPath: manifestReceiptPath, ExpectedReceiptDigest: digest.SHA256(manifestReceiptRaw),
		RuntimeBinding: runtime, ActivationSecret: "ok147-observability-collector-activation",
		MaterializationTime: at,
		ObserverCredential: SubmissionStageCredentialSource{
			AuthorityIdentity: digest.SHA256([]byte("collector-target-cluster-uid")),
			TokenFile:         tokenPath, TokenDigest: digest.SHA256(token), CAFile: caPath, CABundleDigest: digest.SHA256(ca),
			TokenRequestEvidenceDigest: runnerStageSHA("e"), ExpectedIssuer: "https://kubernetes.default.svc.cluster.local",
			ExpectedSubject: subject, ExpectedAudiences: []string{"https://kubernetes.default.svc"},
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		},
		WebhookTokenPath: webhookPath, QueryTokenPath: queryPath,
		PublicEndpoint: "https://192.0.2.44:8443", ListenAddress: "0.0.0.0:8443",
		TLSCertificatePath: certificatePath, TLSPrivateKeyPath: privateKeyPath, MaximumRecordAge: 10 * time.Minute,
	}, cleanup
}

func collectorRuntimeBindingFiles(t *testing.T, manifest VerifiedFullRunExecutionManifest, ca []byte, at time.Time) RuntimeBindingMaterialFileConfig {
	t.Helper()
	plan := manifest.plan
	root := t.TempDir()
	predecessors := []stagereceipt.Verified{}
	sources := make([]StageReceiptSource, 0, 6)
	targetUID := "collector-target-cluster-uid"
	var lifecycleEvidence, networkEvidence string
	results := []struct {
		id, mutation, operation, evidence string
	}{
		{"provider-prerequisites", "ATTEMPTED", runnerStageSHA("1"), runnerStageSHA("2")},
		{"cluster-lifecycle", "ATTEMPTED", runnerStageSHA("3"), runnerStageSHA("4")},
		{"lifecycle-observation", "NOT_APPLICABLE", "", runnerStageSHA("5")},
		{"enablement", "ATTEMPTED", runnerStageSHA("6"), runnerStageSHA("7")},
		{"network-observation", "NOT_APPLICABLE", "", runnerStageSHA("8")},
		{"runtime-binding", "NOT_APPLICABLE", "", runnerStageSHA("9")},
	}
	for index, result := range results {
		var verified stagereceipt.Verified
		var err error
		if result.id == "cluster-lifecycle" {
			verified, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, digest.SHA256([]byte(targetUID)), at.Add(time.Duration(index-7)*time.Minute))
			lifecycleEvidence = result.evidence
		} else {
			verified, err = stagereceipt.New(plan, result.id, predecessors, "SUCCEEDED", result.mutation, result.operation, result.evidence, at.Add(time.Duration(index-7)*time.Minute))
			if result.id == "network-observation" {
				networkEvidence = result.evidence
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		sources = appendStageReceipt(t, root, sources, verified, result.id+".json")
		predecessors = []stagereceipt.Verified{verified}
	}
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND",
		PlanDigest: plan.PlanDigest, IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		Target: RuntimeBindingTarget{
			Name: plan.ContractIdentity.Name, CAPIClusterUID: targetUID, TargetIdentityScheme: "capi-cluster-uid/v1",
			WorkloadAPIEndpoint: "https://192.0.2.147:6443", WorkloadAPICAData: base64.StdEncoding.EncodeToString(ca),
			WorkloadAPICADigest: digest.SHA256(ca), KubeSystemUID: "collector-kube-system-uid",
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "collector-storage-class-uid", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: lifecycleEvidence, NetworkEvidenceDigest: networkEvidence},
	}
	materialRaw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding",
		PlanDigest: plan.PlanDigest, IntentRevision: plan.IntentRevision,
		TargetClusterUIDDigest: digest.SHA256([]byte(targetUID)), WorkloadAPICADigest: digest.SHA256(ca),
		KubeSystemUIDDigest:       digest.SHA256([]byte(material.Target.KubeSystemUID)),
		LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)),
		LifecycleEvidenceDigest:   lifecycleEvidence, NetworkEvidenceDigest: networkEvidence,
		PrivateMaterialDigest: digest.SHA256(materialRaw), PersistentMutationAllowed: false,
	}
	if err := os.WriteFile(manifest.document.RuntimeBinding.MaterialPath, materialRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest.document.RuntimeBinding.ReceiptPath, receiptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return RuntimeBindingMaterialFileConfig{
		Bundle: StageResumeConfig{
			PlanPath: manifest.document.Plan.Path,
			PlanExpected: stageplan.Expected{
				ContractIdentity: plan.ContractIdentity, IntentRevision: plan.IntentRevision,
				EnablementRevision: plan.EnablementRevision, PlatformRevision: plan.PlatformRevision,
				ExecutionFixture: plan.ExecutionFixture, InfrastructureAuthority: plan.Authorities.Infrastructure,
				ManagementAuthority: plan.Authorities.Management, GitOpsAuthority: plan.Authorities.GitOps,
			},
			Receipts: sources,
		},
		MaterialPath: manifest.document.RuntimeBinding.MaterialPath, ReceiptPath: manifest.document.RuntimeBinding.ReceiptPath,
	}
}

func collectorTestCA(t *testing.T, at time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(401), Subject: pkix.Name{CommonName: "ok147-collector-test-ca"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncodeCertificate(raw)
}

func collectorServerCredential(t *testing.T, at time.Time, address net.IP) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(402), Subject: pkix.Name{CommonName: "ok147-collector"},
		NotBefore: at.Add(-time.Hour), NotAfter: at.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{address},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateRaw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pemEncodeCertificate(raw), pemEncodeECPrivateKey(privateRaw)
}

func pemEncodeCertificate(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func pemEncodeECPrivateKey(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})
}

func mustDecodeCollectorSecret(t *testing.T, secret postRuntimeActivationSecret, key string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(secret.Data[key])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
