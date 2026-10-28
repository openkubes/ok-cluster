package targetadmission

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestRenderWebhookConfigurationIsFailClosedAndNameScoped(t *testing.T) {
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _ := testCertificates(t, InstallServiceDNS)
	raw, err := RenderWebhookConfiguration(policy, InstallNamespace, InstallService, ca)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	webhooks := document["webhooks"].([]any)
	if len(webhooks) != 6 {
		t.Fatalf("expected six narrowly scoped resource webhooks, got %d", len(webhooks))
	}
	foundExpectedCreate := false
	for _, item := range webhooks {
		entry := item.(map[string]any)
		if entry["failurePolicy"] != "Fail" || entry["matchPolicy"] != "Exact" || entry["sideEffects"] != "None" || entry["timeoutSeconds"] != 5 {
			t.Fatalf("unsafe webhook behavior: %#v", entry)
		}
		if _, exists := entry["namespaceSelector"]; exists {
			t.Fatal("namespace selector creates a bypassable scope")
		}
		if _, exists := entry["objectSelector"]; exists {
			t.Fatal("object selector creates a bypassable scope")
		}
		conditions := entry["matchConditions"].([]any)
		condition := conditions[0].(map[string]any)["expression"].(string)
		if strings.Contains(condition, `request.operation == "CREATE"`) && strings.Contains(condition, `request.name == "target-a"`) {
			foundExpectedCreate = true
		}
	}
	if !foundExpectedCreate {
		t.Fatal("exact target name and CREATE CEL condition missing")
	}
}

func TestRenderWebhookRequiresValidServiceAndCABundle(t *testing.T) {
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _ := testCertificates(t, InstallServiceDNS)
	if _, err := RenderWebhookConfiguration(policy, "Bad_Namespace", InstallService, ca); err == nil {
		t.Fatal("invalid namespace accepted")
	}
	if _, err := RenderWebhookConfiguration(policy, InstallNamespace, "other-service", ca); err == nil {
		t.Fatal("webhook configuration accepted a service identity outside the fixed installation plan")
	}
	if _, err := RenderWebhookConfiguration(policy, InstallNamespace, InstallService, []byte("not a CA")); err == nil {
		t.Fatal("invalid CA accepted")
	}
	for _, caBundle := range [][]byte{
		append([]byte("untrusted prefix\n"), ca...),
		append(append([]byte(nil), ca...), []byte("\nuntrusted suffix")...),
	} {
		if _, err := RenderWebhookConfiguration(policy, InstallNamespace, InstallService, caBundle); err == nil {
			t.Fatal("CA bundle with non-PEM data was accepted")
		}
	}
}

func TestValidateWebhookKubernetesVersion(t *testing.T) {
	for _, version := range []string{"v1.30.0", "v1.35.5+rke2r1", "v1.40.0+vendor.2"} {
		if err := ValidateWebhookKubernetesVersion(version); err != nil {
			t.Errorf("supported version %q rejected: %v", version, err)
		}
	}
	for _, version := range []string{"v1.29.9", "v0.99.0", "v1.30.0-alpha.1", "v1.30.0-rc.1", "1.35.0", "garbage"} {
		if err := ValidateWebhookKubernetesVersion(version); err == nil {
			t.Errorf("unsupported or invalid version %q accepted", version)
		}
	}
}

func TestNewTLSServerRequiresCertificateServiceIdentity(t *testing.T) {
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	caPEM, certPEM, keyPEM := testCertificates(t, InstallServiceDNS)
	server, err := NewTLSServer(policy, certPEM, keyPEM, caPEM, InstallServiceDNS)
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS12 || server.TLSConfig.Certificates[0].Leaf == nil ||
		server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.WriteTimeout != 10*time.Second ||
		server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 32*1024 {
		t.Fatal("TLS server certificate or HTTP resource bounds are not configured")
	}
	if _, err := NewTLSServer(policy, certPEM, keyPEM, caPEM, "wrong.ok-system.svc"); err == nil {
		t.Fatal("certificate with wrong service DNS name accepted")
	}
	otherCA, otherCert, otherKey := testCertificates(t, "other-service.other-namespace.svc")
	if _, err := NewTLSServer(policy, otherCert, otherKey, otherCA, "other-service.other-namespace.svc"); err == nil {
		t.Fatal("valid certificate for a different service identity was accepted")
	}
	wrongCA, _, _ := testCertificates(t, "different-ca")
	if _, err := NewTLSServer(policy, certPEM, keyPEM, wrongCA, InstallServiceDNS); err == nil {
		t.Fatal("serving certificate not chained to webhook CA accepted")
	}
}

func TestTLSServerHealthEndpointIsReadOnlyAndMethodBound(t *testing.T) {
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	caPEM, certPEM, keyPEM := testCertificates(t, InstallServiceDNS)
	server, err := NewTLSServer(policy, certPEM, keyPEM, caPEM, InstallServiceDNS)
	if err != nil {
		t.Fatal(err)
	}
	probe := httptest.NewUnstartedServer(server.Handler)
	probe.TLS = server.TLSConfig.Clone()
	probe.StartTLS()
	defer probe.Close()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA did not parse")
	}
	transport := probe.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: InstallServiceDNS}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	response, err := client.Get(probe.URL + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health GET status = %d, want 200", response.StatusCode)
	}
	for _, method := range []string{http.MethodPost, http.MethodHead, http.MethodOptions} {
		req, err := http.NewRequest(method, probe.URL+HealthPath, strings.NewReader("ignored"))
		if err != nil {
			t.Fatal(err)
		}
		response, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("health %s status = %d, want 405", method, response.StatusCode)
		}
	}
	response, err = client.Get(probe.URL + "/unrelated")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unrelated path status = %d, want 404", response.StatusCode)
	}
}

func TestTLSServerBindsAdmissionRouteToActualPeerCIDR(t *testing.T) {
	config := policyConfig()
	policy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, certPEM, keyPEM := testCertificates(t, InstallServiceDNS)
	server, err := NewTLSServer(policy, certPEM, keyPEM, caPEM, InstallServiceDNS)
	if err != nil {
		t.Fatal(err)
	}
	review, err := json.Marshal(validReview(config))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		remoteAddr string
		forwarded  string
		wantStatus int
	}{
		{name: "trusted peer", remoteAddr: "127.0.0.1:8443", wantStatus: http.StatusOK},
		{name: "untrusted peer cannot spoof forwarded address", remoteAddr: "192.0.2.8:8443", forwarded: "127.0.0.1", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, AdmissionPath, bytes.NewReader(review))
			request.RemoteAddr = tc.remoteAddr
			request.Header.Set("Content-Type", "application/json")
			if tc.forwarded != "" {
				request.Header.Set("X-Forwarded-For", tc.forwarded)
			}
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("HTTP status = %d, want %d", response.Code, tc.wantStatus)
			}
		})
	}
}

func testCertificates(t *testing.T, dns string) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(dns); ip != nil {
		leafTemplate.DNSNames = nil
		leafTemplate.IPAddresses = []net.IP{ip}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return caPEM, leafPEM, keyPEM
}
