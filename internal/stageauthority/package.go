package stageauthority

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimePackageFormat = "ok147-bounded-stage-authority-runtime-package/v2"

var (
	imageDigestPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`)
	dnsLabelPattern       = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	storageRequestPattern = regexp.MustCompile(`^[1-9][0-9]*(?:Ki|Mi|Gi)$`)
)

type RuntimePackageConfig struct {
	PolicyPath           string
	ExpectedPolicyDigest string
	PrivateKeyPath       string
	TokenFile            string
	TLSCertPath          string
	TLSKeyPath           string
	Template             []byte
	TemplateDigest       string
	ImageDigest          string
	Namespace            string
	Name                 string
	PrivateSecret        string
	StorageClass         string
	StorageRequest       string
	ServiceIP            string
}

type RuntimePackageReceipt struct {
	Format                string   `json:"format"`
	State                 string   `json:"state"`
	PackageDigest         string   `json:"packageDigest"`
	SecretObjectDigest    string   `json:"secretObjectDigest"`
	RuntimeObjectsDigest  string   `json:"runtimeObjectsDigest"`
	TemplateDigest        string   `json:"templateDigest"`
	PolicyDigest          string   `json:"policyDigest"`
	KeyID                 string   `json:"keyId"`
	TLSIdentityDigest     string   `json:"tlsIdentityDigest"`
	ServiceIdentityDigest string   `json:"serviceIdentityDigest"`
	ImageDigest           string   `json:"imageDigest"`
	PrivateFileCount      int      `json:"privateFileCount"`
	ObjectKinds           []string `json:"objectKinds"`
	MutationAllowed       bool     `json:"mutationAllowed"`
}

type VerifiedRuntimePackage struct {
	raw      []byte
	receipt  RuntimePackageReceipt
	verified bool
}

// BuildRuntimePackage creates one private Secret plus the exact tokenless
// runtime envelope. It is local-only and grants no installation authority.
func BuildRuntimePackage(config RuntimePackageConfig) (VerifiedRuntimePackage, error) {
	if !digestPattern.MatchString(config.ExpectedPolicyDigest) || !digestPattern.MatchString(config.TemplateDigest) ||
		digest.SHA256(config.Template) != config.TemplateDigest || !imageDigestPattern.MatchString(config.ImageDigest) ||
		config.Namespace != "openkubes-execution-system" || config.Name != "ok147-stage-authority" ||
		config.PrivateSecret != "ok147-stage-authority-private" || !dnsLabelPattern.MatchString(config.StorageClass) ||
		!storageRequestPattern.MatchString(config.StorageRequest) || !validRuntimeServiceIP(config.ServiceIP) {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority runtime package binding is invalid")
	}
	policyRaw, err := readPrivateRegular(config.PolicyPath, maximumPolicyBytes, false)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read bounded stage authority package policy")
	}
	_, policyDigest, err := verifyPolicy(policyRaw)
	if err != nil || policyDigest != config.ExpectedPolicyDigest {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority package policy differs")
	}
	privateRaw, err := readPrivateRegular(config.PrivateKeyPath, maximumCredentialBytes, true)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read bounded stage authority package key")
	}
	_, keyID, err := parsePrivateKey(privateRaw)
	if err != nil {
		return VerifiedRuntimePackage{}, err
	}
	tokenRaw, err := readPrivateRegular(config.TokenFile, maximumCredentialBytes, true)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read bounded stage authority package token")
	}
	token := strings.TrimSuffix(string(tokenRaw), "\n")
	if !validBearerToken([]byte(token)) {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority package token is invalid")
	}
	certRaw, err := readPrivateRegular(config.TLSCertPath, 128*1024, false)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read bounded stage authority package TLS certificate")
	}
	tlsKeyRaw, err := readPrivateRegular(config.TLSKeyPath, 128*1024, true)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("read bounded stage authority package TLS key")
	}
	certificate, err := tls.X509KeyPair(certRaw, tlsKeyRaw)
	if err != nil || len(certificate.Certificate) == 0 {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority package TLS identity is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !certificateBindsRuntimeServiceIP(leaf, config.ServiceIP) {
		return VerifiedRuntimePackage{}, errors.New("bounded stage authority TLS identity does not bind the Service IP")
	}
	secret := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "immutable": true, "type": "Opaque",
		"metadata": map[string]any{
			"name": config.PrivateSecret, "namespace": config.Namespace,
			"labels":      map[string]any{"app.kubernetes.io/name": config.Name},
			"annotations": map[string]any{"openkubes.io/policy-digest": policyDigest, "openkubes.io/key-id": keyID},
		},
		"data": map[string]any{
			"policy.json": base64.StdEncoding.EncodeToString(policyRaw), "authority.key": base64.StdEncoding.EncodeToString(privateRaw),
			"client-token": base64.StdEncoding.EncodeToString(tokenRaw), "tls.crt": base64.StdEncoding.EncodeToString(certRaw),
			"tls.key": base64.StdEncoding.EncodeToString(tlsKeyRaw),
		},
	}
	secretRaw, err := json.Marshal(secret)
	if err != nil {
		return VerifiedRuntimePackage{}, errors.New("encode bounded stage authority private Secret")
	}
	runtimeRaw, err := RenderRuntimeTemplate(config.Template, RuntimeTemplateValues{
		ImageDigest: config.ImageDigest, Namespace: config.Namespace, Name: config.Name, PrivateSecret: config.PrivateSecret,
		PolicyDigest: policyDigest, KeyID: keyID, StorageClass: config.StorageClass, StorageRequest: config.StorageRequest, ServiceIP: config.ServiceIP,
	})
	if err != nil {
		return VerifiedRuntimePackage{}, err
	}
	packageRaw := bytes.Join([][]byte{secretRaw, runtimeRaw}, []byte("\n---\n"))
	receipt := RuntimePackageReceipt{
		Format: RuntimePackageFormat, State: "VERIFIED", PackageDigest: digest.SHA256(packageRaw),
		SecretObjectDigest: digest.SHA256(secretRaw), RuntimeObjectsDigest: digest.SHA256(runtimeRaw), TemplateDigest: config.TemplateDigest,
		PolicyDigest: policyDigest, KeyID: keyID, TLSIdentityDigest: digest.SHA256(certificate.Certificate[0]),
		ServiceIdentityDigest: digest.SHA256([]byte(config.ServiceIP)), ImageDigest: config.ImageDigest,
		PrivateFileCount: 5, ObjectKinds: []string{"Secret", "ServiceAccount", "PersistentVolumeClaim", "Service", "NetworkPolicy", "StatefulSet"}, MutationAllowed: false,
	}
	return VerifiedRuntimePackage{raw: packageRaw, receipt: receipt, verified: true}, nil
}

func (packaged VerifiedRuntimePackage) PrivateBytes() ([]byte, error) {
	if err := verifyRuntimePackage(packaged); err != nil {
		return nil, err
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedRuntimePackage) Receipt() (RuntimePackageReceipt, error) {
	if err := verifyRuntimePackage(packaged); err != nil {
		return RuntimePackageReceipt{}, err
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string{}, receipt.ObjectKinds...)
	return receipt, nil
}

func verifyRuntimePackage(packaged VerifiedRuntimePackage) error {
	receipt := packaged.receipt
	if !packaged.verified || receipt.Format != RuntimePackageFormat || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != receipt.PackageDigest || receipt.PrivateFileCount != 5 || len(receipt.ObjectKinds) != 6 {
		return errors.New("bounded stage authority runtime package was not produced by verification")
	}
	for _, value := range []string{receipt.PackageDigest, receipt.SecretObjectDigest, receipt.RuntimeObjectsDigest, receipt.TemplateDigest, receipt.PolicyDigest, receipt.KeyID, receipt.TLSIdentityDigest, receipt.ServiceIdentityDigest} {
		if !digestPattern.MatchString(value) {
			return errors.New("bounded stage authority runtime package identity is invalid")
		}
	}
	parts := bytes.SplitN(packaged.raw, []byte("\n---\n"), 2)
	if len(parts) != 2 || digest.SHA256(parts[0]) != receipt.SecretObjectDigest || digest.SHA256(parts[1]) != receipt.RuntimeObjectsDigest {
		return errors.New("bounded stage authority runtime package components changed")
	}
	return nil
}

type RuntimeTemplateValues struct {
	ImageDigest    string
	Namespace      string
	Name           string
	PrivateSecret  string
	PolicyDigest   string
	KeyID          string
	StorageClass   string
	StorageRequest string
	ServiceIP      string
}

func RenderRuntimeTemplate(template []byte, values RuntimeTemplateValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 512*1024 || !imageDigestPattern.MatchString(values.ImageDigest) ||
		values.Namespace != "openkubes-execution-system" || values.Name != "ok147-stage-authority" || values.PrivateSecret != "ok147-stage-authority-private" ||
		!digestPattern.MatchString(values.PolicyDigest) || !digestPattern.MatchString(values.KeyID) || !dnsLabelPattern.MatchString(values.StorageClass) ||
		!storageRequestPattern.MatchString(values.StorageRequest) || !validRuntimeServiceIP(values.ServiceIP) {
		return nil, errors.New("bounded stage authority runtime template input is invalid")
	}
	replacements := map[string]string{
		"${OK147_IMAGE_DIGEST}": values.ImageDigest, "${OK147_AUTHORITY_NAMESPACE}": values.Namespace,
		"${OK147_AUTHORITY_NAME}": values.Name, "${OK147_PRIVATE_SECRET}": values.PrivateSecret,
		"${OK147_POLICY_DIGEST}": values.PolicyDigest, "${OK147_KEY_ID}": values.KeyID,
		"${OK147_STORAGE_CLASS}": values.StorageClass, "${OK147_STORAGE_REQUEST}": values.StorageRequest,
		"${OK147_AUTHORITY_SERVICE_IP}": values.ServiceIP,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, errors.New("bounded stage authority runtime template lacks a required placeholder")
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("bounded stage authority runtime template contains an unknown placeholder")
	}
	return []byte(result), nil
}

func validRuntimeServiceIP(raw string) bool {
	address, err := netip.ParseAddr(raw)
	return err == nil && address.Is4() && address.IsPrivate() && !address.IsLoopback() && !address.IsUnspecified()
}

func certificateBindsRuntimeServiceIP(certificate *x509.Certificate, raw string) bool {
	expected, err := netip.ParseAddr(raw)
	if err != nil || certificate == nil {
		return false
	}
	for _, value := range certificate.IPAddresses {
		observed, ok := netip.AddrFromSlice(value)
		if ok && observed.Unmap() == expected.Unmap() {
			return true
		}
	}
	return false
}
