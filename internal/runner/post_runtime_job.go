package runner

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type PostRuntimeExecutionJobValues struct {
	RunID                string
	ImageDigest          string
	ActivationSecret     string
	BundleDigest         string
	ManifestDigest       string
	ManagementAPIURL     string
	ManagementAPICIDR    string
	WorkloadAPIURL       string
	WorkloadAPICIDR      string
	ArgoAPIURL           string
	ArgoAPICIDR          string
	AuthorizationAPIURL  string
	AuthorizationAPICIDR string
	RecoveryMode         string
}

// RenderPostRuntimeExecutionJobTemplate binds the complete Stage 8-12 process
// to one immutable projected bundle and four exact network destinations. The
// init container converts only the indexed Secret projection into regular
// private files before the executor can start.
func RenderPostRuntimeExecutionJobTemplate(template []byte, values PostRuntimeExecutionJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("post-runtime Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") ||
		!dnsLabel.MatchString(values.ActivationSecret) || len(values.ActivationSecret) > 63 || !strings.HasPrefix(values.ActivationSecret, "ok147-") {
		return nil, errors.New("post-runtime Job object identity is invalid")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("post-runtime Job image is not digest-bound")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(values.BundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(values.ManifestDigest) {
		return nil, errors.New("post-runtime Job bundle identity is invalid")
	}
	managementPort, managementEndpoint, err := exactAPIEndpoint(values.ManagementAPIURL, values.ManagementAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("post-runtime management endpoint: %w", err)
	}
	workloadPort, workloadEndpoint, err := exactAPIEndpoint(values.WorkloadAPIURL, values.WorkloadAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("post-runtime workload endpoint: %w", err)
	}
	argoPort, argoEndpoint, err := exactAPIEndpoint(values.ArgoAPIURL, values.ArgoAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("post-runtime Argo endpoint: %w", err)
	}
	authorizationPort, _, err := exactPostRuntimeAuthorizationEndpoint(values.AuthorizationAPIURL, values.AuthorizationAPICIDR)
	if err != nil {
		return nil, err
	}
	if managementEndpoint == workloadEndpoint || managementEndpoint == argoEndpoint || workloadEndpoint == argoEndpoint {
		return nil, errors.New("post-runtime management, workload and Argo endpoints must be distinct")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_IMAGE_DIGEST}": values.ImageDigest,
		"${OK147_ACTIVATION_SECRET}": values.ActivationSecret, "${OK147_BUNDLE_DIGEST}": values.BundleDigest,
		"${OK147_MANIFEST_DIGEST}":     values.ManifestDigest,
		"${OK147_MANAGEMENT_API_CIDR}": values.ManagementAPICIDR, "${OK147_MANAGEMENT_API_PORT}": managementPort,
		"${OK147_WORKLOAD_API_CIDR}": values.WorkloadAPICIDR, "${OK147_WORKLOAD_API_PORT}": workloadPort,
		"${OK147_ARGO_API_CIDR}": values.ArgoAPICIDR, "${OK147_ARGO_API_PORT}": argoPort,
		"${OK147_AUTHORIZATION_API_CIDR}": values.AuthorizationAPICIDR, "${OK147_AUTHORIZATION_API_PORT}": authorizationPort,
	}
	switch values.RecoveryMode {
	case "":
		replacements["${OK147_RECOVERY_RECEIPT_ITEMS}"] = ""
	case "target-credential":
		replacements["${OK147_RECOVERY_RECEIPT_ITEMS}"] = "              - {key: input.08-target-credential.json, path: input/08-target-credential.json}"
	case "target-registration":
		replacements["${OK147_RECOVERY_RECEIPT_ITEMS}"] = "              - {key: input.08-target-credential.json, path: input/08-target-credential.json}\n              - {key: input.09-target-registration.json, path: input/09-target-registration.json}"
	default:
		return nil, errors.New("post-runtime Job recovery mode is invalid")
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("post-runtime Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("post-runtime Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}

func exactPostRuntimeAuthorizationEndpoint(rawURL, rawCIDR string) (string, string, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "/v1/stage-authorizations" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", "", errors.New("post-runtime authorization URL must be the exact HTTPS authority endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil {
		return "", "", errors.New("post-runtime authorization URL must use an IP address")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("post-runtime authorization URL must contain an explicit valid port")
	}
	prefix, err := netip.ParsePrefix(rawCIDR)
	if err != nil || prefix.Bits() != address.BitLen() || prefix.Addr() != address {
		return "", "", errors.New("post-runtime authorization CIDR must bind only the endpoint IP")
	}
	return strconv.Itoa(port), netip.AddrPortFrom(address, uint16(port)).String(), nil
}
