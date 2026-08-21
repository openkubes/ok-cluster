package runner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
)

func TestKubernetesObservabilityPlatformCapabilityFactoryResolvesLazily(t *testing.T) {
	root := t.TempDir()
	requests := 0
	server, ca, certificate, key := newObservabilityFactoryTLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	caPath := filepath.Join(root, "workload-ca.crt")
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	kubeconfigPath := filepath.Join(root, "workload.kubeconfig")
	if err := os.WriteFile(kubeconfigPath, testClientKubeconfig(server.URL, ca, certificate, key), 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceMaterial := newSignedObservabilityEvidenceMaterial(t)
	evidenceSource := openSignedObservabilityEvidenceSource(t, evidenceMaterial, evidenceMaterial.observedAt.Add(time.Minute))
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	workloadCalls := 0
	boundAuthority := KubernetesAuthorityConfig{
		Endpoint: server.URL, AuthorityIdentity: evidenceMaterial.identity.TargetClusterUID, KubeconfigFile: kubeconfigPath,
		CAFile: caPath, CABundleDigest: digest.SHA256(ca),
	}
	openedTransport, err := openBoundedKubernetesAuthorityTransport(boundAuthority)
	if err != nil || !openedTransport.clientCertificate || digest.SHA256(openedTransport.caData) != boundAuthority.CABundleDigest {
		t.Fatalf("test workload authority is invalid: cert=%v ca=%v err=%v", openedTransport.clientCertificate, digest.SHA256(openedTransport.caData) == boundAuthority.CABundleDigest, err)
	}
	workload := WorkloadAuthorityResolverFunc(func(_ context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
		workloadCalls++
		bound := boundAuthority
		bound.AuthorityIdentity = policy.TargetClusterUID
		return bound, nil
	})
	factory, err := NewKubernetesObservabilityPlatformCapabilityFactory(KubernetesObservabilityPlatformCapabilityFactoryConfig{
		WorkloadAuthority: workload, IndependentEvidence: evidenceSource, Fixture: capabilityFixtureConfig(), Profile: profile,
		PollInterval: time.Millisecond, Clock: func() time.Time { return evidenceMaterial.observedAt.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	platformProfile := runnerPlatformProfile()
	binding := FullRunPlatformCapabilityBinding{
		Namespace: "ok-observability", Timeout: time.Minute, CleanupTimeout: 10 * time.Second,
		IntentRevision: platformProfile.IntentRevision, PlatformRevision: platformProfile.PlatformRevision,
		ExecutionFixture: platformProfile.ExecutionFixture, ContractDigest: platformProfile.CapabilityContractDigest,
		ExecutableDigest: platformProfile.CapabilityExecutableDigest,
	}
	resolver, err := factory.OpenFullRunPlatformCapability(binding)
	if err != nil || workloadCalls != 0 || requests != 0 {
		t.Fatalf("factory open was not inert: workload=%d requests=%d err=%v", workloadCalls, requests, err)
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: platformProfile.IntentRevision, EnablementRevision: digestOf("e"),
		PlatformRevision: platformProfile.PlatformRevision, TargetClusterUID: evidenceMaterial.identity.TargetClusterUID,
		Required: []string{"PlatformReady"},
	}
	source, err := resolver.ResolvePlatformCapability(context.Background(), policy, platformProfile)
	if err != nil || source == nil || workloadCalls != 1 || requests != 0 {
		t.Fatalf("lazy capability resolution differs: source=%T workload=%d requests=%d err=%v", source, workloadCalls, requests, err)
	}
	if _, err := resolver.ResolvePlatformCapability(context.Background(), policy, platformProfile); err == nil || workloadCalls != 1 || requests != 0 {
		t.Fatal("single-use capability resolver repeated authority resolution")
	}
}

func newObservabilityFactoryTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(201), Subject: pkix.Name{CommonName: "ok147-observability-factory-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(serial int64, commonName string, usages []x509.ExtKeyUsage, addresses []net.IP) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, IPAddresses: addresses,
		}
		certificateDER, err := x509.CreateCertificate(rand.Reader, template, caTemplate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}
	serverCertificate, serverKey := sign(202, "127.0.0.1", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCertificate, clientKey := sign(203, "ok147-observability-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	tlsCertificate, err := tls.X509KeyPair(serverCertificate, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{tlsCertificate}}
	server.StartTLS()
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), clientCertificate, clientKey
}

func TestKubernetesObservabilityPlatformCapabilityFactoryRejectsForeignProfileBeforeAuthority(t *testing.T) {
	evidenceMaterial := newSignedObservabilityEvidenceMaterial(t)
	evidenceSource := openSignedObservabilityEvidenceSource(t, evidenceMaterial, evidenceMaterial.observedAt.Add(time.Minute))
	checkProfile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	workloadCalls := 0
	factory, err := NewKubernetesObservabilityPlatformCapabilityFactory(KubernetesObservabilityPlatformCapabilityFactoryConfig{
		WorkloadAuthority: WorkloadAuthorityResolverFunc(func(context.Context, observation.Policy) (KubernetesAuthorityConfig, error) {
			workloadCalls++
			return KubernetesAuthorityConfig{}, nil
		}),
		IndependentEvidence: evidenceSource, Fixture: capabilityFixtureConfig(), Profile: checkProfile,
		PollInterval: time.Millisecond, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	platformProfile := runnerPlatformProfile()
	resolver, err := factory.OpenFullRunPlatformCapability(FullRunPlatformCapabilityBinding{
		Namespace: "ok-observability", Timeout: time.Minute, CleanupTimeout: 10 * time.Second,
		IntentRevision: platformProfile.IntentRevision, PlatformRevision: platformProfile.PlatformRevision,
		ExecutionFixture: platformProfile.ExecutionFixture, ContractDigest: platformProfile.CapabilityContractDigest,
		ExecutableDigest: platformProfile.CapabilityExecutableDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := observation.Policy{
		Format: observation.PolicyFormat, IntentRevision: platformProfile.IntentRevision, EnablementRevision: digestOf("e"),
		PlatformRevision: platformProfile.PlatformRevision, TargetClusterUID: evidenceMaterial.identity.TargetClusterUID,
		Required: []string{"PlatformReady"},
	}
	platformProfile.CapabilityExecutableDigest = digestOf("9")
	if _, err := resolver.ResolvePlatformCapability(context.Background(), policy, platformProfile); err == nil || workloadCalls != 0 {
		t.Fatal("foreign profile reached workload authority")
	}
}
