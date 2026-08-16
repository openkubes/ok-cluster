package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const lifecycleObservationJobOverhead = time.Minute

// LifecycleObservationStageJobValues contain only public runtime identities.
// Credential contents remain in separately materialized Secrets.
type LifecycleObservationStageJobValues struct {
	RunID                      string
	ImageDigest                string
	Expected                   stageplan.Expected
	InputConfigMap             string
	ReceiptPrefixDigest        string
	LedgerAPIURL               string
	LedgerAPICIDR              string
	LedgerCredentialSecret     string
	ManagementAPIURL           string
	ManagementAPICIDR          string
	ManagementCredentialSecret string
	PollInterval               time.Duration
	PollTimeout                time.Duration
}

// RenderLifecycleObservationStageJobTemplate performs validated literal
// substitution for exactly one lifecycle-observation NetworkPolicy and Job.
func RenderLifecycleObservationStageJobTemplate(template []byte, values LifecycleObservationStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("lifecycle observation Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("lifecycle observation Job run ID is invalid")
	}
	for _, value := range []string{values.InputConfigMap, values.LedgerCredentialSecret, values.ManagementCredentialSecret} {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("lifecycle observation Job object name is invalid")
		}
	}
	if values.InputConfigMap == values.LedgerCredentialSecret || values.InputConfigMap == values.ManagementCredentialSecret || values.LedgerCredentialSecret == values.ManagementCredentialSecret {
		return nil, errors.New("lifecycle observation Job input and credentials must use distinct objects")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("lifecycle observation Job image is not digest-bound")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(values.ReceiptPrefixDigest) {
		return nil, errors.New("lifecycle observation Job receipt-prefix digest is invalid")
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("lifecycle observation Job expected binding: %w", err)
	}
	if values.PollInterval < time.Second || values.PollInterval > 5*time.Minute || values.PollTimeout < values.PollInterval || values.PollTimeout > 6*time.Hour || values.PollInterval%time.Second != 0 || values.PollTimeout%time.Second != 0 {
		return nil, errors.New("lifecycle observation Job polling window is invalid")
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("lifecycle observation Job ledger endpoint: %w", err)
	}
	managementPort, managementEndpoint, err := exactAPIEndpoint(values.ManagementAPIURL, values.ManagementAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("lifecycle observation Job management endpoint: %w", err)
	}
	if ledgerEndpoint != managementEndpoint || ledgerPort != managementPort {
		return nil, errors.New("lifecycle observation ledger and management source must use the same verified management API")
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
		"${OK147_MANAGEMENT_API_URL}": values.ManagementAPIURL, "${OK147_MANAGEMENT_CREDENTIAL_SECRET}": values.ManagementCredentialSecret,
		"${OK147_POLL_INTERVAL}": values.PollInterval.String(), "${OK147_POLL_TIMEOUT}": values.PollTimeout.String(),
		"${OK147_ACTIVE_DEADLINE_SECONDS}": strconv.FormatInt(int64((values.PollTimeout+lifecycleObservationJobOverhead)/time.Second), 10),
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("lifecycle observation Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("lifecycle observation Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
