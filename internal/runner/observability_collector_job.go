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

type ObservabilityCollectorJobValues struct {
	RunID                string
	ImageDigest          string
	ActivationSecret     string
	ActivationDigest     string
	ManifestDigest       string
	RuntimeBindingDigest string
	PublicEndpointDigest string
	PublicEndpoint       string
	WorkloadAPIURL       string
	WorkloadAPICIDR      string
	AlertSourceCIDR      string
}

// RenderObservabilityCollectorJobTemplate binds one time-limited collector
// Service, exact ingress/egress policy and non-retrying Job. It performs only
// literal replacement after validating every environment-specific identity.
func RenderObservabilityCollectorJobTemplate(template []byte, values ObservabilityCollectorJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("observability collector Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	for _, name := range []string{values.RunID, values.ActivationSecret} {
		if !dnsLabel.MatchString(name) || len(name) > 63 || !strings.HasPrefix(name, "ok147-") {
			return nil, errors.New("observability collector Job object identity is invalid")
		}
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("observability collector Job image is not digest-bound")
	}
	for _, identity := range []string{
		values.ActivationDigest, values.ManifestDigest, values.RuntimeBindingDigest, values.PublicEndpointDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(identity) {
			return nil, errors.New("observability collector Job digest identity is invalid")
		}
	}
	endpoint, err := url.Parse(values.PublicEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Port() == "" {
		return nil, errors.New("observability collector public endpoint is invalid")
	}
	publicAddress, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || !publicAddress.Is4() || publicAddress.IsUnspecified() || publicAddress.IsMulticast() {
		return nil, errors.New("observability collector public endpoint must use one IPv4 address")
	}
	collectorPort, err := strconv.Atoi(endpoint.Port())
	if err != nil || collectorPort < 1 || collectorPort > 65535 {
		return nil, errors.New("observability collector public endpoint port is invalid")
	}
	workloadPort, workloadTarget, err := exactAPIEndpoint(values.WorkloadAPIURL, values.WorkloadAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("observability collector workload endpoint: %w", err)
	}
	if workloadTarget == netip.AddrPortFrom(publicAddress, uint16(collectorPort)).String() {
		return nil, errors.New("observability collector and workload authorities must be distinct")
	}
	alertSource, err := netip.ParsePrefix(values.AlertSourceCIDR)
	if err != nil || !alertSource.IsValid() || !alertSource.Addr().Is4() || alertSource.Addr().IsUnspecified() ||
		alertSource.Bits() < 16 || alertSource.Bits() > 32 || alertSource != alertSource.Masked() {
		return nil, errors.New("observability collector alert source CIDR is invalid or too broad")
	}
	replacements := map[string]string{
		"${OK147_COLLECTOR_RUN_ID}":                 values.RunID,
		"${OK147_IMAGE_DIGEST}":                     values.ImageDigest,
		"${OK147_COLLECTOR_ACTIVATION_SECRET}":      values.ActivationSecret,
		"${OK147_COLLECTOR_ACTIVATION_DIGEST}":      values.ActivationDigest,
		"${OK147_COLLECTOR_MANIFEST_DIGEST}":        values.ManifestDigest,
		"${OK147_COLLECTOR_RUNTIME_BINDING_DIGEST}": values.RuntimeBindingDigest,
		"${OK147_COLLECTOR_PUBLIC_ENDPOINT_DIGEST}": values.PublicEndpointDigest,
		"${OK147_COLLECTOR_PUBLIC_IP}":              publicAddress.String(),
		"${OK147_COLLECTOR_PORT}":                   strconv.Itoa(collectorPort),
		"${OK147_WORKLOAD_API_CIDR}":                values.WorkloadAPICIDR,
		"${OK147_WORKLOAD_API_PORT}":                workloadPort,
		"${OK147_ALERT_SOURCE_CIDR}":                alertSource.String(),
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("observability collector Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("observability collector Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
