package targetadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	AdmissionPath                 = "/validate-target-access"
	HealthPath                    = "/healthz"
	MinimumWebhookKubernetesMinor = 30
)

var kubernetesGitVersionPattern = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.[0-9]+(?:\+[0-9A-Za-z.-]+)?$`)

// ValidateWebhookKubernetesVersion gates the generated CEL-based webhook on
// the target API server's reported GitVersion. The installer must obtain that
// value from the same explicitly identified target before installing policy.
func ValidateWebhookKubernetesVersion(gitVersion string) error {
	parts := kubernetesGitVersionPattern.FindStringSubmatch(gitVersion)
	if len(parts) != 3 {
		return errors.New("target Kubernetes GitVersion is invalid")
	}
	major, majorErr := strconv.Atoi(parts[1])
	minor, minorErr := strconv.Atoi(parts[2])
	if majorErr != nil || minorErr != nil || major < 1 || (major == 1 && minor < MinimumWebhookKubernetesMinor) {
		return errors.New("target Kubernetes must be version 1.30 or later for safe webhook name matching")
	}
	return nil
}

// NewBoundTLSServer is the only supported server activation path: verify the
// independently signed bundle, read the live target identity and Kubernetes
// version over pinned TLS, and only then construct the HTTPS handler. A caller
// cannot start serving on a replacement target or unsupported Kubernetes
// version through this API.
func NewBoundTLSServer(ctx context.Context, signedPolicy []byte, trustedPolicyKey ed25519.PublicKey, targetAPIEndpoint string, targetAPICA, targetReadToken, servingCertificate, servingPrivateKey, webhookCABundle []byte, serviceDNSName string) (*http.Server, string, error) {
	policy, target, err := VerifyBundle(signedPolicy, trustedPolicyKey)
	if err != nil {
		return nil, "", err
	}
	if err := VerifyLiveTargetBinding(ctx, targetAPIEndpoint, targetAPICA, targetReadToken, target); err != nil {
		return nil, "", err
	}
	if _, err := VerifyLiveTargetKubernetesVersion(ctx, targetAPIEndpoint, targetAPICA, targetReadToken); err != nil {
		return nil, "", err
	}
	server, err := NewTLSServer(policy, servingCertificate, servingPrivateKey, webhookCABundle, serviceDNSName)
	if err != nil {
		return nil, "", err
	}
	return server, policy.Digest(), nil
}

// NewTLSServer validates the service identity in the leaf certificate and
// configures a TLS 1.2+ HTTPS server. Kubernetes authenticates the webhook
// server using the CA in the rendered webhook configuration; this is not mTLS.
func NewTLSServer(policy *Policy, certificatePEM, privateKeyPEM, webhookCABundle []byte, serviceDNSName string) (*http.Server, error) {
	if policy == nil || serviceDNSName != InstallServiceDNS || len(certificatePEM) == 0 || len(certificatePEM) > 1024*1024 || len(privateKeyPEM) == 0 || len(privateKeyPEM) > 1024*1024 || !validCABundle(webhookCABundle) {
		return nil, errors.New("target admission policy and service DNS identity are required")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("target admission TLS key pair is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.New("target admission TLS certificate is invalid")
	}
	now := time.Now()
	serverAuth := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if leaf.VerifyHostname(serviceDNSName) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !serverAuth {
		return nil, errors.New("target admission TLS certificate does not cover the service DNS identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(webhookCABundle) {
		return nil, errors.New("target admission webhook CA bundle is invalid")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("target admission certificate chain is invalid")
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: serviceDNSName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		return nil, errors.New("target admission serving certificate is not trusted by the webhook CA bundle")
	}
	certificate.Leaf = leaf
	return &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == HealthPath {
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
				return
			}
			if r.URL.Path != AdmissionPath {
				http.NotFound(w, r)
				return
			}
			Handler(policy).ServeHTTP(w, r)
		}),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}, nil
}

type webhookDocument struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   webhookMetadata `yaml:"metadata"`
	Webhooks   []webhookEntry  `yaml:"webhooks"`
}
type webhookMetadata struct {
	Name string `yaml:"name"`
}
type webhookEntry struct {
	Name                    string              `yaml:"name"`
	AdmissionReviewVersions []string            `yaml:"admissionReviewVersions"`
	ClientConfig            webhookClientConfig `yaml:"clientConfig"`
	FailurePolicy           string              `yaml:"failurePolicy"`
	MatchPolicy             string              `yaml:"matchPolicy"`
	MatchConditions         []webhookCondition  `yaml:"matchConditions"`
	Rules                   []webhookRule       `yaml:"rules"`
	SideEffects             string              `yaml:"sideEffects"`
	TimeoutSeconds          int                 `yaml:"timeoutSeconds"`
}
type webhookClientConfig struct {
	CABundle []byte         `yaml:"caBundle"`
	Service  webhookService `yaml:"service"`
}
type webhookService struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Path      string `yaml:"path"`
	Port      *int32 `yaml:"port"`
}
type webhookCondition struct {
	Name       string `yaml:"name"`
	Expression string `yaml:"expression"`
}
type webhookRule struct {
	APIGroups   []string `yaml:"apiGroups"`
	APIVersions []string `yaml:"apiVersions"`
	Operations  []string `yaml:"operations"`
	Resources   []string `yaml:"resources"`
	Scope       string   `yaml:"scope"`
}

// RenderWebhookConfiguration emits a fail-closed validating webhook narrowly
// matched to the signed policy's exact object names. It requires Kubernetes
// 1.30+ because CEL matchConditions are what prevent unrelated creates of the
// same resource kinds from being sent to the webhook.
func RenderWebhookConfiguration(policy *Policy, serviceNamespace, serviceName string, caBundle []byte) ([]byte, error) {
	if policy == nil || serviceNamespace != InstallNamespace || serviceName != InstallService || !validCABundle(caBundle) {
		return nil, errors.New("target webhook service identity or CA bundle is invalid")
	}
	type ruleKey struct{ group, version, resource, scope string }
	identities := make(map[ruleKey][]projectionIdentity)
	for _, object := range policy.objects {
		group, version := splitAPIVersion(object.identity.APIVersion)
		resource, scope := resourceFor(object.identity.Kind)
		if resource == "" {
			return nil, errors.New("target policy contains unsupported webhook resource")
		}
		key := ruleKey{group: group, version: version, resource: resource, scope: scope}
		identities[key] = append(identities[key], projectionIdentity{namespace: object.identity.Namespace, name: object.identity.Name})
	}
	keys := make([]ruleKey, 0, len(identities))
	for key := range identities {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return strings.Join([]string{a.group, a.version, a.resource, a.scope}, "/") < strings.Join([]string{b.group, b.version, b.resource, b.scope}, "/")
	})
	port := int32(443)
	document := webhookDocument{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingWebhookConfiguration", Metadata: webhookMetadata{Name: "ok147-target-access.openkubes.io"}}
	for _, key := range keys {
		allowed := identities[key]
		sort.Slice(allowed, func(i, j int) bool {
			return allowed[i].namespace+"/"+allowed[i].name < allowed[j].namespace+"/"+allowed[j].name
		})
		terms := make([]string, 0, len(allowed))
		for _, identity := range allowed {
			term := "request.name == " + strconv.Quote(identity.name)
			if key.group != "" {
				term += " && request.resource.group == " + strconv.Quote(key.group)
			}
			if key.group == "" {
				term += " && request.resource.group == \"\""
			}
			term += " && request.resource.resource == " + strconv.Quote(key.resource)
			if key.scope == "Namespaced" {
				term += " && request.namespace == " + strconv.Quote(identity.namespace)
			} else {
				term += " && request.namespace == \"\""
			}
			terms = append(terms, "("+term+")")
		}
		name := fmt.Sprintf("%s.%s.%s.ok147.openkubes.io", key.resource, key.version, strings.ReplaceAll(key.group, ".", "-"))
		if key.group == "" {
			name = fmt.Sprintf("%s.%s.core.ok147.openkubes.io", key.resource, key.version)
		}
		document.Webhooks = append(document.Webhooks, webhookEntry{
			Name: name, AdmissionReviewVersions: []string{"v1"},
			ClientConfig:  webhookClientConfig{CABundle: append([]byte(nil), caBundle...), Service: webhookService{Name: serviceName, Namespace: serviceNamespace, Path: AdmissionPath, Port: &port}},
			FailurePolicy: "Fail", MatchPolicy: "Exact", SideEffects: "None", TimeoutSeconds: 5,
			MatchConditions: []webhookCondition{{Name: "approved-target-object", Expression: "request.operation == \"CREATE\" && (" + strings.Join(terms, " || ") + ")"}},
			Rules:           []webhookRule{{APIGroups: []string{key.group}, APIVersions: []string{key.version}, Operations: []string{"CREATE"}, Resources: []string{key.resource}, Scope: key.scope}},
		})
	}
	raw, err := yaml.Marshal(document)
	if err != nil {
		return nil, errors.New("encode target validating webhook configuration")
	}
	return raw, nil
}

type projectionIdentity struct{ namespace, name string }

func resourceFor(kind string) (string, string) {
	switch kind {
	case "Namespace":
		return "namespaces", "Cluster"
	case "ServiceAccount":
		return "serviceaccounts", "Namespaced"
	case "ClusterRole":
		return "clusterroles", "Cluster"
	case "ClusterRoleBinding":
		return "clusterrolebindings", "Cluster"
	case "Role":
		return "roles", "Namespaced"
	case "RoleBinding":
		return "rolebindings", "Namespaced"
	default:
		return "", ""
	}
}

func validCABundle(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 1024*1024 {
		return false
	}
	remaining := raw
	count := 0
	for {
		trimmed := bytes.TrimSpace(remaining)
		if len(trimmed) == 0 {
			break
		}
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return false
		}
		count++
		remaining = rest
	}
	return count > 0
}
