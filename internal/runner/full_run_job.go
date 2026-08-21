package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

type FullRunExecutionJobValues struct {
	RunID                    string
	ImageDigest              string
	ActivationSecret         string
	EvidenceAuthoritySecret  string
	BundleDigest             string
	ManifestDigest           string
	EvidenceActivationDigest string
	EvidenceKeyID            string
	CollectorCADigest        string
	InfrastructureAPIURL     string
	InfrastructureAPICIDR    string
	ManagementAPIURL         string
	ManagementAPICIDR        string
	WorkloadAPIURL           string
	WorkloadAPICIDR          string
	ArgoAPIURL               string
	ArgoAPICIDR              string
	AuthorizationAPIURL      string
	AuthorizationAPICIDR     string
	CollectorAPIURL          string
	CollectorAPICIDR         string
}

// RenderFullRunExecutionJobTemplate binds one Stage 1-12 executor and one
// independent evidence authority into a single Pod. They share only the
// evidence handoff; neither container can mount the other's private material.
func RenderFullRunExecutionJobTemplate(template []byte, values FullRunExecutionJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("full-run Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	for _, name := range []string{values.RunID, values.ActivationSecret, values.EvidenceAuthoritySecret} {
		if !dnsLabel.MatchString(name) || len(name) > 63 || !strings.HasPrefix(name, "ok147-") {
			return nil, errors.New("full-run Job object identity is invalid")
		}
	}
	if values.ActivationSecret == values.EvidenceAuthoritySecret ||
		!regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("full-run Job private Secret or image identity is invalid")
	}
	for _, identity := range []string{
		values.BundleDigest, values.ManifestDigest, values.EvidenceActivationDigest, values.EvidenceKeyID, values.CollectorCADigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(identity) {
			return nil, errors.New("full-run Job digest identity is invalid")
		}
	}
	endpoints := []struct {
		name, rawURL, cidr string
	}{
		{"infrastructure", values.InfrastructureAPIURL, values.InfrastructureAPICIDR},
		{"management", values.ManagementAPIURL, values.ManagementAPICIDR},
		{"workload", values.WorkloadAPIURL, values.WorkloadAPICIDR},
		{"Argo", values.ArgoAPIURL, values.ArgoAPICIDR},
		{"collector", values.CollectorAPIURL, values.CollectorAPICIDR},
	}
	ports := make(map[string]string, len(endpoints)+1)
	targets := make(map[string]struct{}, len(endpoints)+1)
	for _, endpoint := range endpoints {
		port, target, err := exactAPIEndpoint(endpoint.rawURL, endpoint.cidr)
		if err != nil {
			return nil, fmt.Errorf("full-run %s endpoint: %w", endpoint.name, err)
		}
		if _, exists := targets[target]; exists {
			return nil, errors.New("full-run network authorities must be distinct")
		}
		targets[target], ports[endpoint.name] = struct{}{}, port
	}
	authorizationPort, authorizationTarget, err := exactPostRuntimeAuthorizationEndpoint(values.AuthorizationAPIURL, values.AuthorizationAPICIDR)
	if err != nil {
		return nil, err
	}
	if _, exists := targets[authorizationTarget]; exists {
		return nil, errors.New("full-run authorization authority must be distinct")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_IMAGE_DIGEST}": values.ImageDigest,
		"${OK147_ACTIVATION_SECRET}": values.ActivationSecret, "${OK147_EVIDENCE_AUTHORITY_SECRET}": values.EvidenceAuthoritySecret,
		"${OK147_BUNDLE_DIGEST}": values.BundleDigest, "${OK147_MANIFEST_DIGEST}": values.ManifestDigest,
		"${OK147_EVIDENCE_ACTIVATION_DIGEST}": values.EvidenceActivationDigest,
		"${OK147_EVIDENCE_KEY_ID}":            values.EvidenceKeyID, "${OK147_COLLECTOR_CA_DIGEST}": values.CollectorCADigest,
		"${OK147_INFRASTRUCTURE_API_CIDR}": values.InfrastructureAPICIDR, "${OK147_INFRASTRUCTURE_API_PORT}": ports["infrastructure"],
		"${OK147_MANAGEMENT_API_CIDR}": values.ManagementAPICIDR, "${OK147_MANAGEMENT_API_PORT}": ports["management"],
		"${OK147_WORKLOAD_API_CIDR}": values.WorkloadAPICIDR, "${OK147_WORKLOAD_API_PORT}": ports["workload"],
		"${OK147_ARGO_API_CIDR}": values.ArgoAPICIDR, "${OK147_ARGO_API_PORT}": ports["Argo"],
		"${OK147_AUTHORIZATION_API_CIDR}": values.AuthorizationAPICIDR, "${OK147_AUTHORIZATION_API_PORT}": authorizationPort,
		"${OK147_COLLECTOR_API_CIDR}": values.CollectorAPICIDR, "${OK147_COLLECTOR_API_PORT}": ports["collector"],
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("full-run Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("full-run Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
