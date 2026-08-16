package runner

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JobTemplateValues are the complete environment-specific identities required
// to materialize the bounded Job and its exact API NetworkPolicy.
type JobTemplateValues struct {
	RunID             string
	ImageDigest       string
	EvaluationTime    string
	KubernetesAPIURL  string
	KubernetesAPICIDR string
	InputConfigMap    string
}

var jobPlaceholders = map[string]func(JobTemplateValues) string{
	"${OK147_RUN_ID}":              func(values JobTemplateValues) string { return values.RunID },
	"${OK147_IMAGE_DIGEST}":        func(values JobTemplateValues) string { return values.ImageDigest },
	"${OK147_EVALUATION_TIME}":     func(values JobTemplateValues) string { return values.EvaluationTime },
	"${OK147_KUBERNETES_API_URL}":  func(values JobTemplateValues) string { return values.KubernetesAPIURL },
	"${OK147_KUBERNETES_API_CIDR}": func(values JobTemplateValues) string { return values.KubernetesAPICIDR },
	"${OK147_INPUT_CONFIGMAP}":     func(values JobTemplateValues) string { return values.InputConfigMap },
}

// RenderJobTemplate validates every substituted identity before performing
// literal replacement. It does not execute a template language or shell.
func RenderJobTemplate(template []byte, values JobTemplateValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("runner Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("runner Job run ID is invalid")
	}
	if !dnsLabel.MatchString(values.InputConfigMap) || len(values.InputConfigMap) > 63 {
		return nil, errors.New("runner input ConfigMap name is invalid")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("runner image is not bound to a SHA-256 digest")
	}
	if _, err := time.Parse(time.RFC3339, values.EvaluationTime); err != nil {
		return nil, errors.New("runner evaluation time is not RFC3339")
	}
	endpoint, err := url.Parse(values.KubernetesAPIURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Port() != "443" {
		return nil, errors.New("runner Kubernetes API URL must be an exact HTTPS IP endpoint on port 443")
	}
	apiAddress, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil {
		return nil, errors.New("runner Kubernetes API URL must use an IP address")
	}
	prefix, err := netip.ParsePrefix(values.KubernetesAPICIDR)
	if err != nil || prefix.Bits() != apiAddress.BitLen() || prefix.Addr() != apiAddress {
		return nil, errors.New("runner Kubernetes API CIDR must bind only the endpoint IP")
	}

	result := string(template)
	for placeholder, extract := range jobPlaceholders {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("runner Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, extract(values))
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("runner Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
