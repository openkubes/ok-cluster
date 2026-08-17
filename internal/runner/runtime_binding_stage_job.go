package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

type RuntimeBindingStageJobValues struct {
	RunID                       string
	ImageDigest                 string
	Expected                    stageplan.Expected
	InputConfigMap              string
	ReceiptPrefixDigest         string
	LedgerAPIURL                string
	LedgerAPICIDR               string
	LedgerCredentialSecret      string
	PersistenceCredentialSecret string
	WorkloadAPIURL              string
	WorkloadAPICIDR             string
	WorkloadCredentialSecret    string
	WorkloadBindingDigest       string
}

// RenderRuntimeBindingStageJobTemplate validates and substitutes exactly one
// two-endpoint NetworkPolicy and one immutable-Secret runtime-binding Job.
func RenderRuntimeBindingStageJobTemplate(template []byte, values RuntimeBindingStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("runtime binding Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("runtime binding Job run ID is invalid")
	}
	names := []string{values.InputConfigMap, values.LedgerCredentialSecret, values.PersistenceCredentialSecret, values.WorkloadCredentialSecret}
	seen := map[string]struct{}{}
	for _, value := range names {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("runtime binding Job object name is invalid")
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, errors.New("runtime binding Job inputs and credentials must use distinct objects")
		}
		seen[value] = struct{}{}
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("runtime binding Job image is not digest-bound")
	}
	for _, value := range []string{values.ReceiptPrefixDigest, values.WorkloadBindingDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return nil, errors.New("runtime binding Job semantic digest is invalid")
		}
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("runtime binding Job expected binding: %w", err)
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("runtime binding Job management endpoint: %w", err)
	}
	workloadPort, workloadEndpoint, err := exactAPIEndpoint(values.WorkloadAPIURL, values.WorkloadAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("runtime binding Job workload endpoint: %w", err)
	}
	if workloadEndpoint == ledgerEndpoint {
		return nil, errors.New("runtime binding management and workload endpoints must differ")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_IMAGE_DIGEST}": values.ImageDigest,
		"${OK147_CONTRACT_NAMESPACE}": values.Expected.ContractIdentity.Namespace, "${OK147_CONTRACT_NAME}": values.Expected.ContractIdentity.Name,
		"${OK147_R}": values.Expected.IntentRevision, "${OK147_E}": values.Expected.EnablementRevision,
		"${OK147_P}": values.Expected.PlatformRevision, "${OK147_FIXTURE}": values.Expected.ExecutionFixture,
		"${OK147_INFRA_AUTHORITY}": values.Expected.InfrastructureAuthority, "${OK147_MGMT_AUTHORITY}": values.Expected.ManagementAuthority,
		"${OK147_GITOPS_AUTHORITY}": values.Expected.GitOpsAuthority,
		"${OK147_INPUT_CONFIGMAP}":  values.InputConfigMap, "${OK147_RECEIPT_PREFIX_DIGEST}": values.ReceiptPrefixDigest,
		"${OK147_LEDGER_API_URL}": values.LedgerAPIURL, "${OK147_LEDGER_API_CIDR}": values.LedgerAPICIDR,
		"${OK147_LEDGER_API_PORT}": ledgerPort, "${OK147_LEDGER_CREDENTIAL_SECRET}": values.LedgerCredentialSecret,
		"${OK147_PERSISTENCE_CREDENTIAL_SECRET}": values.PersistenceCredentialSecret,
		"${OK147_WORKLOAD_API_CIDR}":             values.WorkloadAPICIDR, "${OK147_WORKLOAD_API_PORT}": workloadPort,
		"${OK147_WORKLOAD_CREDENTIAL_SECRET}": values.WorkloadCredentialSecret, "${OK147_WORKLOAD_BINDING_DIGEST}": values.WorkloadBindingDigest,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("runtime binding Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("runtime binding Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
