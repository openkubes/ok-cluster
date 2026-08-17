package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

type AggregateEvidenceStageJobValues struct {
	RunID                      string
	ImageDigest                string
	Expected                   stageplan.Expected
	InputConfigMap             string
	ReceiptPrefixDigest        string
	AggregateProfileDigest     string
	NetworkProfileDigest       string
	PlatformProfileDigest      string
	LedgerAPIURL               string
	LedgerAPICIDR              string
	LedgerCredentialSecret     string
	ManagementAPIURL           string
	ManagementAPICIDR          string
	ManagementCredentialSecret string
	WorkloadAPIURL             string
	WorkloadAPICIDR            string
	WorkloadCredentialSecret   string
	ArgoAPIURL                 string
	ArgoAPICIDR                string
	ArgoCredentialSecret       string
	RuntimeBindingSecret       string
	PlatformCapabilitySecret   string
	PlatformCapabilityDigest   string
}

// RenderAggregateEvidenceStageJobTemplate binds the final one-pass evaluator
// to exact management, workload and GitOps APIs and seven distinct mounted
// inputs. It performs literal rendering only and contacts no authority.
func RenderAggregateEvidenceStageJobTemplate(template []byte, values AggregateEvidenceStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("aggregate evidence Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("aggregate evidence Job run ID is invalid")
	}
	names := []string{
		values.InputConfigMap, values.LedgerCredentialSecret, values.ManagementCredentialSecret,
		values.WorkloadCredentialSecret, values.ArgoCredentialSecret, values.RuntimeBindingSecret,
		values.PlatformCapabilitySecret,
	}
	seen := map[string]struct{}{}
	for _, value := range names {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("aggregate evidence Job object name is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errors.New("aggregate evidence Job inputs and private objects must be distinct")
		}
		seen[value] = struct{}{}
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("aggregate evidence Job image is not digest-bound")
	}
	for _, value := range []string{values.ReceiptPrefixDigest, values.AggregateProfileDigest, values.NetworkProfileDigest, values.PlatformProfileDigest, values.PlatformCapabilityDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return nil, errors.New("aggregate evidence Job semantic digest is invalid")
		}
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("aggregate evidence Job expected binding: %w", err)
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("aggregate evidence Job ledger endpoint: %w", err)
	}
	managementPort, managementEndpoint, err := exactAPIEndpoint(values.ManagementAPIURL, values.ManagementAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("aggregate evidence Job management endpoint: %w", err)
	}
	if ledgerEndpoint != managementEndpoint || ledgerPort != managementPort {
		return nil, errors.New("aggregate evidence ledger and management source must use the same verified API")
	}
	workloadPort, workloadEndpoint, err := exactAPIEndpoint(values.WorkloadAPIURL, values.WorkloadAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("aggregate evidence Job workload endpoint: %w", err)
	}
	argoPort, argoEndpoint, err := exactAPIEndpoint(values.ArgoAPIURL, values.ArgoAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("aggregate evidence Job Argo endpoint: %w", err)
	}
	if workloadEndpoint == managementEndpoint || argoEndpoint == managementEndpoint || argoEndpoint == workloadEndpoint {
		return nil, errors.New("aggregate evidence management, workload and Argo endpoints must be distinct")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_IMAGE_DIGEST}": values.ImageDigest,
		"${OK147_CONTRACT_NAMESPACE}": values.Expected.ContractIdentity.Namespace, "${OK147_CONTRACT_NAME}": values.Expected.ContractIdentity.Name,
		"${OK147_R}": values.Expected.IntentRevision, "${OK147_E}": values.Expected.EnablementRevision,
		"${OK147_P}": values.Expected.PlatformRevision, "${OK147_FIXTURE}": values.Expected.ExecutionFixture,
		"${OK147_INFRA_AUTHORITY}": values.Expected.InfrastructureAuthority, "${OK147_MGMT_AUTHORITY}": values.Expected.ManagementAuthority,
		"${OK147_GITOPS_AUTHORITY}": values.Expected.GitOpsAuthority,
		"${OK147_INPUT_CONFIGMAP}":  values.InputConfigMap, "${OK147_RECEIPT_PREFIX_DIGEST}": values.ReceiptPrefixDigest,
		"${OK147_AGGREGATE_PROFILE_DIGEST}": values.AggregateProfileDigest,
		"${OK147_NETWORK_PROFILE_DIGEST}":   values.NetworkProfileDigest, "${OK147_PLATFORM_PROFILE_DIGEST}": values.PlatformProfileDigest,
		"${OK147_LEDGER_API_URL}": values.LedgerAPIURL, "${OK147_LEDGER_API_CIDR}": values.LedgerAPICIDR,
		"${OK147_LEDGER_API_PORT}": ledgerPort, "${OK147_LEDGER_CREDENTIAL_SECRET}": values.LedgerCredentialSecret,
		"${OK147_MANAGEMENT_API_URL}": values.ManagementAPIURL, "${OK147_MANAGEMENT_CREDENTIAL_SECRET}": values.ManagementCredentialSecret,
		"${OK147_WORKLOAD_API_URL}": values.WorkloadAPIURL, "${OK147_WORKLOAD_API_CIDR}": values.WorkloadAPICIDR,
		"${OK147_WORKLOAD_API_PORT}": workloadPort, "${OK147_WORKLOAD_CREDENTIAL_SECRET}": values.WorkloadCredentialSecret,
		"${OK147_ARGO_API_URL}": values.ArgoAPIURL, "${OK147_ARGO_API_CIDR}": values.ArgoAPICIDR,
		"${OK147_ARGO_API_PORT}": argoPort, "${OK147_ARGO_CREDENTIAL_SECRET}": values.ArgoCredentialSecret,
		"${OK147_RUNTIME_BINDING_SECRET}":     values.RuntimeBindingSecret,
		"${OK147_PLATFORM_CAPABILITY_SECRET}": values.PlatformCapabilitySecret,
		"${OK147_PLATFORM_CAPABILITY_DIGEST}": values.PlatformCapabilityDigest,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("aggregate evidence Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("aggregate evidence Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
