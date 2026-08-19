package runner

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// SubmissionStageJobValues bind one non-retrying Job to the exact verified
// artifact, credential and network identities needed by stage run.
type SubmissionStageJobValues struct {
	RunID                     string
	StageID                   string
	ImageDigest               string
	EvaluationTime            string
	Expected                  stageplan.Expected
	InputConfigMap            string
	ReceiptPrefixDigest       string
	LedgerAPIURL              string
	LedgerAPICIDR             string
	LedgerCredentialSecret    string
	AuthorityAPIURL           string
	AuthorityAPICIDR          string
	AuthorityCredentialSecret string
}

// RenderSubmissionStageJobTemplate performs only validated literal
// substitutions. The sole stage-dependent YAML fragments are code-owned.
func RenderSubmissionStageJobTemplate(template []byte, values SubmissionStageJobValues) ([]byte, error) {
	if len(template) == 0 || len(template) > 1024*1024 {
		return nil, errors.New("submission stage Job template size is invalid")
	}
	dnsLabel := regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	if !dnsLabel.MatchString(values.RunID) || len(values.RunID) > 63 || !strings.HasPrefix(values.RunID, "ok147-") {
		return nil, errors.New("submission stage Job run ID is invalid")
	}
	for _, value := range []string{values.InputConfigMap, values.LedgerCredentialSecret, values.AuthorityCredentialSecret} {
		if !dnsLabel.MatchString(value) || len(value) > 63 {
			return nil, errors.New("submission stage Job object name is invalid")
		}
	}
	if values.LedgerCredentialSecret == values.AuthorityCredentialSecret {
		return nil, errors.New("submission stage Job credentials must use distinct Secrets")
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$`).MatchString(values.ImageDigest) {
		return nil, errors.New("submission stage Job image is not digest-bound")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(values.ReceiptPrefixDigest) {
		return nil, errors.New("submission stage Job receipt-prefix digest is invalid")
	}
	if _, err := time.Parse(time.RFC3339, values.EvaluationTime); err != nil {
		return nil, errors.New("submission stage Job evaluation time is not RFC3339")
	}
	if err := stageplan.ValidateExpected(values.Expected); err != nil {
		return nil, fmt.Errorf("submission stage Job expected binding: %w", err)
	}
	ledgerPort, ledgerEndpoint, err := exactAPIEndpoint(values.LedgerAPIURL, values.LedgerAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("submission stage Job ledger endpoint: %w", err)
	}
	authorityPort, authorityEndpoint, err := exactAPIEndpoint(values.AuthorityAPIURL, values.AuthorityAPICIDR)
	if err != nil {
		return nil, fmt.Errorf("submission stage Job authority endpoint: %w", err)
	}
	receiptMount, receiptItem := "", ""
	switch values.StageID {
	case "provider-prerequisites":
		if authorityEndpoint == ledgerEndpoint {
			return nil, errors.New("provider stage authority must be outside the management ledger endpoint")
		}
	case "cluster-lifecycle":
		if authorityEndpoint != ledgerEndpoint {
			return nil, errors.New("cluster lifecycle authority must use the management ledger endpoint")
		}
	default:
		return nil, errors.New("submission stage Job supports only Contract-to-CAPI stages")
	}
	replacements := map[string]string{
		"${OK147_RUN_ID}": values.RunID, "${OK147_STAGE_ID}": values.StageID,
		"${OK147_IMAGE_DIGEST}": values.ImageDigest, "${OK147_EVALUATION_TIME}": values.EvaluationTime,
		"${OK147_CONTRACT_NAMESPACE}": values.Expected.ContractIdentity.Namespace, "${OK147_CONTRACT_NAME}": values.Expected.ContractIdentity.Name,
		"${OK147_R}": values.Expected.IntentRevision, "${OK147_E}": values.Expected.EnablementRevision,
		"${OK147_P}": values.Expected.PlatformRevision, "${OK147_FIXTURE}": values.Expected.ExecutionFixture,
		"${OK147_INFRA_AUTHORITY}": values.Expected.InfrastructureAuthority, "${OK147_MGMT_AUTHORITY}": values.Expected.ManagementAuthority,
		"${OK147_GITOPS_AUTHORITY}": values.Expected.GitOpsAuthority, "${OK147_INPUT_CONFIGMAP}": values.InputConfigMap,
		"${OK147_RECEIPT_PREFIX_DIGEST}": values.ReceiptPrefixDigest,
		"${OK147_LEDGER_API_URL}":        values.LedgerAPIURL, "${OK147_LEDGER_API_CIDR}": values.LedgerAPICIDR,
		"${OK147_LEDGER_API_PORT}": ledgerPort, "${OK147_LEDGER_CREDENTIAL_SECRET}": values.LedgerCredentialSecret,
		"${OK147_AUTHORITY_API_URL}": values.AuthorityAPIURL, "${OK147_AUTHORITY_API_CIDR}": values.AuthorityAPICIDR,
		"${OK147_AUTHORITY_API_PORT}": authorityPort, "${OK147_AUTHORITY_CREDENTIAL_SECRET}": values.AuthorityCredentialSecret,
		"${OK147_RECEIPT_VOLUME_MOUNT}": receiptMount, "${OK147_RECEIPT_CONFIGMAP_ITEM}": receiptItem,
	}
	result := string(template)
	for placeholder, value := range replacements {
		if !strings.Contains(result, placeholder) {
			return nil, fmt.Errorf("submission stage Job template lacks %s", placeholder)
		}
		result = strings.ReplaceAll(result, placeholder, value)
	}
	if strings.Contains(result, "${") {
		return nil, errors.New("submission stage Job template contains an unknown placeholder")
	}
	return []byte(result), nil
}

func exactAPIEndpoint(rawURL, rawCIDR string) (string, string, error) {
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", "", errors.New("API URL must be an exact HTTPS IP endpoint")
	}
	address, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil {
		return "", "", errors.New("API URL must use an IP address")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", "", errors.New("API URL must contain an explicit valid port")
	}
	prefix, err := netip.ParsePrefix(rawCIDR)
	if err != nil || prefix.Bits() != address.BitLen() || prefix.Addr() != address {
		return "", "", errors.New("API CIDR must bind only the endpoint IP")
	}
	return strconv.Itoa(port), netip.AddrPortFrom(address, uint16(port)).String(), nil
}
