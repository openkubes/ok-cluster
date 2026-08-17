package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// TargetAccessStageJobValues bind one non-retrying Job to the exact verified
// target-access input, its independently expected object identities, and the
// distinct ledger and workload APIs.
type TargetAccessStageJobValues struct {
	RunID                    string
	ImageDigest              string
	EvaluationTime           string
	Expected                 stageplan.Expected
	InputConfigMap           string
	ReceiptPrefixDigest      string
	ObservabilityNamespace   string
	ManagerServiceAccount    string
	ClusterRole              string
	ClusterRoleBinding       string
	PlatformRole             string
	PlatformRoleBinding      string
	KubeSystemRole           string
	KubeSystemRoleBinding    string
	LedgerAPIURL             string
	LedgerAPICIDR            string
	LedgerCredentialSecret   string
	WorkloadAPIURL           string
	WorkloadAPICIDR          string
	WorkloadCredentialSecret string
	WorkloadBindingDigest    string
}

// RenderTargetAccessStageJobTemplate performs validated literal substitution
// for exactly one target-access NetworkPolicy and Job. It does not contact or
// mutate either Kubernetes API.
func RenderTargetAccessStageJobTemplate(template []byte, values TargetAccessStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("target-access stage Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("target-access stage Job run ID is invalid")
	}
	names := []string{
		values.InputConfigMap, values.ObservabilityNamespace, values.ManagerServiceAccount,
		values.ClusterRole, values.ClusterRoleBinding, values.PlatformRole,
		values.PlatformRoleBinding, values.KubeSystemRole, values.KubeSystemRoleBinding,
		values.LedgerCredentialSecret, values.WorkloadCredentialSecret,
	}
	for _, value := range names {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("target-access stage Job object name is invalid")
		}
	}
	if values.InputConfigMap == values.LedgerCredentialSecret || values.InputConfigMap == values.WorkloadCredentialSecret || values.LedgerCredentialSecret == values.WorkloadCredentialSecret {
		return nil, errors.New("target-access stage Job input and credentials must use distinct objects")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("target-access stage Job image is not digest-bound")
	}
	for _, value := range []string{values.ReceiptPrefixDigest, values.WorkloadBindingDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return nil, errors.New("target-access stage Job semantic digest is invalid")
		}
	}
	if _, err := time.Parse(time.RFC3339, values.EvaluationTime); err != nil {
		return nil, errors.New("target-access stage Job evaluation time is not RFC3339")
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("target-access stage Job expected binding: %w", err)
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("target-access stage Job ledger endpoint: %w", err)
	}
	workloadPort, workloadEndpoint, err := exactAPIEndpoint(values.WorkloadAPIURL, values.WorkloadAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("target-access stage Job workload endpoint: %w", err)
	}
	if workloadEndpoint == ledgerEndpoint {
		return nil, errors.New("target-access ledger and workload endpoints must differ")
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
		"${OK147_OBSERVABILITY_NAMESPACE}": values.ObservabilityNamespace, "${OK147_MANAGER_SERVICEACCOUNT}": values.ManagerServiceAccount,
		"${OK147_CLUSTER_ROLE}": values.ClusterRole, "${OK147_CLUSTER_ROLEBINDING}": values.ClusterRoleBinding,
		"${OK147_PLATFORM_ROLE}": values.PlatformRole, "${OK147_PLATFORM_ROLEBINDING}": values.PlatformRoleBinding,
		"${OK147_KUBE_SYSTEM_ROLE}": values.KubeSystemRole, "${OK147_KUBE_SYSTEM_ROLEBINDING}": values.KubeSystemRoleBinding,
		"${OK147_LEDGER_API_URL}": values.LedgerAPIURL, "${OK147_LEDGER_API_CIDR}": values.LedgerAPICIDR,
		"${OK147_LEDGER_API_PORT}": ledgerPort, "${OK147_LEDGER_CREDENTIAL_SECRET}": values.LedgerCredentialSecret,
		"${OK147_WORKLOAD_API_CIDR}": values.WorkloadAPICIDR, "${OK147_WORKLOAD_API_PORT}": workloadPort,
		"${OK147_WORKLOAD_CREDENTIAL_SECRET}": values.WorkloadCredentialSecret, "${OK147_WORKLOAD_BINDING_DIGEST}": values.WorkloadBindingDigest,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("target-access stage Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("target-access stage Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}
