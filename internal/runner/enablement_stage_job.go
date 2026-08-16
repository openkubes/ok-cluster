package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// EnablementStageJobValues bind one non-retrying Job to the exact verified
// HelmChartProxy input and the management API used by the ledger and writer.
type EnablementStageJobValues struct {
	RunID                      string
	ImageDigest                string
	EvaluationTime             string
	Expected                   stageplan.Expected
	InputConfigMap             string
	ReceiptPrefixDigest        string
	HelmChartProxyName         string
	LedgerAPIURL               string
	LedgerAPICIDR              string
	LedgerCredentialSecret     string
	ManagementAPIURL           string
	ManagementAPICIDR          string
	ManagementCredentialSecret string
}

// RenderEnablementStageJobTemplate performs validated literal substitution for
// exactly one enablement NetworkPolicy and Job. It never renders Helm content.
func RenderEnablementStageJobTemplate(template []byte, values EnablementStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("enablement stage Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("enablement stage Job run ID is invalid")
	}
	for _, value := range []string{values.InputConfigMap, values.HelmChartProxyName, values.LedgerCredentialSecret, values.ManagementCredentialSecret} {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("enablement stage Job object name is invalid")
		}
	}
	if values.InputConfigMap == values.LedgerCredentialSecret || values.InputConfigMap == values.ManagementCredentialSecret || values.LedgerCredentialSecret == values.ManagementCredentialSecret {
		return nil, errors.New("enablement stage Job input and credentials must use distinct objects")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("enablement stage Job image is not digest-bound")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(values.ReceiptPrefixDigest) {
		return nil, errors.New("enablement stage Job receipt-prefix digest is invalid")
	}
	if _, err := time.Parse(time.RFC3339, values.EvaluationTime); err != nil {
		return nil, errors.New("enablement stage Job evaluation time is not RFC3339")
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("enablement stage Job expected binding: %w", err)
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("enablement stage Job ledger endpoint: %w", err)
	}
	managementPort, managementEndpoint, err := exactAPIEndpoint(values.ManagementAPIURL, values.ManagementAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("enablement stage Job management endpoint: %w", err)
	}
	if ledgerEndpoint != managementEndpoint || ledgerPort != managementPort {
		return nil, errors.New("enablement ledger and writer must use the same verified management API")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_IMAGE_DIGEST}": values.ImageDigest,
		"${OK147_EVALUATION_TIME}":    values.EvaluationTime,
		"${OK147_CONTRACT_NAMESPACE}": values.Expected.ContractIdentity.Namespace, "${OK147_CONTRACT_NAME}": values.Expected.ContractIdentity.Name,
		"${OK147_R}": values.Expected.IntentRevision, "${OK147_E}": values.Expected.EnablementRevision,
		"${OK147_P}": values.Expected.PlatformRevision, "${OK147_FIXTURE}": values.Expected.ExecutionFixture,
		"${OK147_INFRA_AUTHORITY}": values.Expected.InfrastructureAuthority, "${OK147_MGMT_AUTHORITY}": values.Expected.ManagementAuthority,
		"${OK147_GITOPS_AUTHORITY}": values.Expected.GitOpsAuthority,
		"${OK147_INPUT_CONFIGMAP}":  values.InputConfigMap, "${OK147_RECEIPT_PREFIX_DIGEST}": values.ReceiptPrefixDigest,
		"${OK147_HELMCHARTPROXY_NAME}": values.HelmChartProxyName,
		"${OK147_LEDGER_API_URL}":      values.LedgerAPIURL, "${OK147_LEDGER_API_CIDR}": values.LedgerAPICIDR,
		"${OK147_LEDGER_API_PORT}": ledgerPort, "${OK147_LEDGER_CREDENTIAL_SECRET}": values.LedgerCredentialSecret,
		"${OK147_MANAGEMENT_API_URL}": values.ManagementAPIURL, "${OK147_MANAGEMENT_CREDENTIAL_SECRET}": values.ManagementCredentialSecret,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("enablement stage Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("enablement stage Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
