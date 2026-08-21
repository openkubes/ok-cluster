package runner

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	FreshRunV3BindingFormat        = "ok147-fresh-run-v3-binding/v1"
	runnerPublicationReceiptFormat = "ok147-runner-publication-receipt/v1"
	boundedRunnerImage             = "ghcr.io/openkubes/ok-cluster-runner"
	maximumFreshRunV3ReceiptBytes  = 1024 * 1024
)

var (
	freshRunSourceSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
	freshRunVersion   = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	freshRunWorkflow  = regexp.MustCompile(`^https://github\.com/openkubes/ok-cluster/actions/runs/[1-9][0-9]*$`)
)

type freshRunPublicationAttestation struct {
	ManifestDigest string   `json:"manifestDigest"`
	PredicateTypes []string `json:"predicateTypes"`
}

type freshRunPublicationReceipt struct {
	Format                              string                                    `json:"format"`
	Image                               string                                    `json:"image"`
	Digest                              string                                    `json:"digest"`
	SourceSHA                           string                                    `json:"sourceSha"`
	Version                             string                                    `json:"version"`
	PublicationContractDigest           string                                    `json:"publicationContractDigest"`
	WorkflowRunURL                      string                                    `json:"workflowRunUrl"`
	PlatformManifestDigests             map[string]string                         `json:"platformManifestDigests"`
	Attestations                        map[string]freshRunPublicationAttestation `json:"attestations"`
	GitHubAttestationVerificationDigest string                                    `json:"githubAttestationVerificationDigest"`
	PullbackByDigestVerified            bool                                      `json:"pullbackByDigestVerified"`
	NetworkPublicationPerformed         bool                                      `json:"networkPublicationPerformed"`
	DeploymentPerformed                 bool                                      `json:"deploymentPerformed"`
	ClusterContactPerformed             bool                                      `json:"clusterContactPerformed"`
}

// FreshRunV3BindingConfig identifies three independently produced public
// receipts. Expected file digests are required so a caller cannot silently
// substitute another publication or package while creating the binding.
type FreshRunV3BindingConfig struct {
	PublicationReceiptPath           string
	ExpectedPublicationReceiptDigest string
	ExpectedSourceSHA                string
	FullRunPackageReceiptPath        string
	ExpectedFullRunPackageDigest     string
	CollectorPackageReceiptPath      string
	ExpectedCollectorPackageDigest   string
}

// FreshRunV3BindingReceipt proves that the exact published runner can execute
// both sides of one collector-backed full run. It grants no publication,
// launch, credential use or Kubernetes mutation.
type FreshRunV3BindingReceipt struct {
	Format                        string `json:"format"`
	State                         string `json:"state"`
	BindingDigest                 string `json:"bindingDigest"`
	SourceSHA                     string `json:"sourceSha"`
	ImageDigest                   string `json:"imageDigest"`
	PublicationReceiptDigest      string `json:"publicationReceiptDigest"`
	FullRunPackageReceiptDigest   string `json:"fullRunPackageReceiptDigest"`
	CollectorPackageReceiptDigest string `json:"collectorPackageReceiptDigest"`
	FullRunPackageDigest          string `json:"fullRunPackageDigest"`
	CollectorPackageDigest        string `json:"collectorPackageDigest"`
	SourceManifestDigest          string `json:"sourceManifestDigest"`
	ExecutionManifestDigest       string `json:"executionManifestDigest"`
	PlanDigest                    string `json:"planDigest"`
	RuntimeBindingDigest          string `json:"runtimeBindingDigest"`
	EvidenceActivationDigest      string `json:"evidenceActivationDigest"`
	EvidenceKeyID                 string `json:"evidenceKeyId"`
	ReceiverIdentityDigest        string `json:"receiverIdentityDigest"`
	CollectorProfileDigest        string `json:"collectorProfileDigest"`
	CollectorEndpointDigest       string `json:"collectorEndpointDigest"`
	CollectorTLSCertificateDigest string `json:"collectorTlsCertificateDigest"`
	MutationAllowed               bool   `json:"mutationAllowed"`
}

// BindFreshRunV3 verifies the exact publication, executor package and
// collector package identities entirely offline.
func BindFreshRunV3(config FreshRunV3BindingConfig) (FreshRunV3BindingReceipt, error) {
	if !freshRunSourceSHA.MatchString(config.ExpectedSourceSHA) {
		return FreshRunV3BindingReceipt{}, errors.New("fresh-run source SHA is invalid")
	}
	publicationRaw, err := loadFreshRunReceipt(config.PublicationReceiptPath, config.ExpectedPublicationReceiptDigest)
	if err != nil {
		return FreshRunV3BindingReceipt{}, errors.New("load fresh-run publication receipt")
	}
	var publication freshRunPublicationReceipt
	if err := jsonstrict.Decode(publicationRaw, &publication); err != nil || verifyFreshRunPublicationReceipt(publication, config.ExpectedSourceSHA) != nil {
		return FreshRunV3BindingReceipt{}, errors.New("verify fresh-run publication receipt")
	}
	fullRunRaw, err := loadFreshRunReceipt(config.FullRunPackageReceiptPath, config.ExpectedFullRunPackageDigest)
	if err != nil {
		return FreshRunV3BindingReceipt{}, errors.New("load fresh-run executor package receipt")
	}
	var fullRun FullRunExecutionActivationPackageReceipt
	if err := jsonstrict.Decode(fullRunRaw, &fullRun); err != nil || verifyFreshRunPackageReceipt(fullRun) != nil {
		return FreshRunV3BindingReceipt{}, errors.New("verify fresh-run executor package receipt")
	}
	collectorRaw, err := loadFreshRunReceipt(config.CollectorPackageReceiptPath, config.ExpectedCollectorPackageDigest)
	if err != nil {
		return FreshRunV3BindingReceipt{}, errors.New("load fresh-run collector package receipt")
	}
	var collector ObservabilityCollectorRuntimePackageReceipt
	if err := jsonstrict.Decode(collectorRaw, &collector); err != nil || verifyFreshRunCollectorReceipt(collector) != nil {
		return FreshRunV3BindingReceipt{}, errors.New("verify fresh-run collector package receipt")
	}
	image := publication.Image + "@" + publication.Digest
	if fullRun.SourceManifestDigest != collector.ManifestDigest || fullRun.CollectorAuthorityDigest != collector.PublicEndpointDigest ||
		fullRun.CollectorCADigest != collector.TLSCertificateDigest || fullRun.ImageDigest != image || collector.ImageDigest != image {
		return FreshRunV3BindingReceipt{}, errors.New("fresh-run executor and collector identities differ")
	}
	receipt := FreshRunV3BindingReceipt{
		Format: FreshRunV3BindingFormat, State: "VERIFIED_NOT_AUTHORIZED", SourceSHA: publication.SourceSHA,
		ImageDigest: image, PublicationReceiptDigest: config.ExpectedPublicationReceiptDigest,
		FullRunPackageReceiptDigest: config.ExpectedFullRunPackageDigest, CollectorPackageReceiptDigest: config.ExpectedCollectorPackageDigest,
		FullRunPackageDigest: fullRun.PackageDigest, CollectorPackageDigest: collector.PackageDigest,
		SourceManifestDigest: fullRun.SourceManifestDigest, ExecutionManifestDigest: fullRun.ManifestDigest,
		PlanDigest: fullRun.PlanDigest, RuntimeBindingDigest: collector.RuntimeBindingDigest,
		EvidenceActivationDigest: fullRun.EvidenceActivationDigest, EvidenceKeyID: fullRun.EvidenceKeyID,
		ReceiverIdentityDigest: collector.ReceiverIdentityDigest, CollectorProfileDigest: collector.ProfileDigest,
		CollectorEndpointDigest: collector.PublicEndpointDigest, CollectorTLSCertificateDigest: collector.TLSCertificateDigest,
		MutationAllowed: false,
	}
	receipt.BindingDigest, err = freshRunV3BindingDigest(receipt)
	if err != nil || verifyFreshRunV3BindingReceipt(receipt) != nil {
		return FreshRunV3BindingReceipt{}, errors.New("construct fresh-run v3 binding")
	}
	return receipt, nil
}

func loadFreshRunReceipt(path, expectedDigest string) ([]byte, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("expected receipt digest is invalid")
	}
	raw, err := readBoundedRegular(path, maximumFreshRunV3ReceiptBytes)
	if err != nil || digest.SHA256(raw) != expectedDigest {
		return nil, errors.New("receipt differs from expected identity")
	}
	return raw, nil
}

func verifyFreshRunPublicationReceipt(receipt freshRunPublicationReceipt, sourceSHA string) error {
	if receipt.Format != runnerPublicationReceiptFormat || receipt.Image != boundedRunnerImage || receipt.SourceSHA != sourceSHA ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.Digest) || !freshRunVersion.MatchString(receipt.Version) ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.PublicationContractDigest) || !freshRunWorkflow.MatchString(receipt.WorkflowRunURL) ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.GitHubAttestationVerificationDigest) || !receipt.PullbackByDigestVerified ||
		!receipt.NetworkPublicationPerformed || receipt.DeploymentPerformed || receipt.ClusterContactPerformed {
		return errors.New("publication identity is incomplete")
	}
	platforms := []string{"linux/amd64", "linux/arm64"}
	if len(receipt.PlatformManifestDigests) != len(platforms) || len(receipt.Attestations) != len(platforms) {
		return errors.New("publication platform set differs")
	}
	for _, platform := range platforms {
		manifest := receipt.PlatformManifestDigests[platform]
		attestation, ok := receipt.Attestations[manifest]
		predicates := append([]string(nil), attestation.PredicateTypes...)
		sort.Strings(predicates)
		if !stageReceiptPrefixDigestPattern.MatchString(manifest) || !ok || !stageReceiptPrefixDigestPattern.MatchString(attestation.ManifestDigest) ||
			len(predicates) != 2 || predicates[0] != "https://slsa.dev/provenance/v1" || predicates[1] != "https://spdx.dev/Document" {
			return errors.New("publication attestation set differs")
		}
	}
	return nil
}

func verifyFreshRunPackageReceipt(receipt FullRunExecutionActivationPackageReceipt) error {
	if receipt.Format != FullRunExecutionActivationPackageFormat || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		len(receipt.ObjectKinds) != 4 || receipt.ObjectKinds[0] != "Secret" || receipt.ObjectKinds[1] != "Secret" ||
		receipt.ObjectKinds[2] != "NetworkPolicy" || receipt.ObjectKinds[3] != "Job" {
		return errors.New("executor package identity is incomplete")
	}
	for _, value := range []string{receipt.PackageDigest, receipt.SourceManifestDigest, receipt.ManifestDigest, receipt.PlanDigest,
		receipt.EvidenceActivationDigest, receipt.EvidenceKeyID, receipt.CollectorAuthorityDigest, receipt.CollectorCADigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("executor package digest is invalid")
		}
	}
	if !capabilityImageDigestPattern.MatchString(receipt.ImageDigest) {
		return errors.New("executor package image identity is invalid")
	}
	return nil
}

func verifyFreshRunCollectorReceipt(receipt ObservabilityCollectorRuntimePackageReceipt) error {
	if receipt.Format != ObservabilityCollectorRuntimePackageFormat || receipt.State != "VERIFIED" || receipt.MutationAllowed ||
		len(receipt.ObjectKinds) != 4 || receipt.ObjectKinds[0] != "Secret" || receipt.ObjectKinds[1] != "Service" ||
		receipt.ObjectKinds[2] != "NetworkPolicy" || receipt.ObjectKinds[3] != "Job" ||
		!capabilityImageDigestPattern.MatchString(receipt.ImageDigest) {
		return errors.New("collector package identity is incomplete")
	}
	for _, value := range []string{receipt.PackageDigest, receipt.ManifestDigest, receipt.RuntimeBindingDigest,
		receipt.PublicEndpointDigest, receipt.TLSCertificateDigest, receipt.ReceiverIdentityDigest, receipt.ProfileDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("collector package digest is invalid")
		}
	}
	return nil
}

func freshRunV3BindingDigest(receipt FreshRunV3BindingReceipt) (string, error) {
	receipt.BindingDigest = ""
	raw, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	return digest.SHA256(raw), nil
}

func verifyFreshRunV3BindingReceipt(receipt FreshRunV3BindingReceipt) error {
	if receipt.Format != FreshRunV3BindingFormat || receipt.State != "VERIFIED_NOT_AUTHORIZED" || receipt.MutationAllowed ||
		!freshRunSourceSHA.MatchString(receipt.SourceSHA) || !capabilityImageDigestPattern.MatchString(receipt.ImageDigest) {
		return errors.New("fresh-run v3 binding identity is incomplete")
	}
	for _, value := range []string{receipt.BindingDigest, receipt.PublicationReceiptDigest, receipt.FullRunPackageReceiptDigest,
		receipt.CollectorPackageReceiptDigest, receipt.FullRunPackageDigest, receipt.CollectorPackageDigest,
		receipt.SourceManifestDigest, receipt.ExecutionManifestDigest, receipt.PlanDigest, receipt.RuntimeBindingDigest,
		receipt.EvidenceActivationDigest, receipt.EvidenceKeyID, receipt.ReceiverIdentityDigest,
		receipt.CollectorProfileDigest, receipt.CollectorEndpointDigest, receipt.CollectorTLSCertificateDigest} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("fresh-run v3 binding digest is invalid")
		}
	}
	expected, err := freshRunV3BindingDigest(receipt)
	if err != nil || expected != receipt.BindingDigest {
		return errors.New("fresh-run v3 binding digest differs")
	}
	return nil
}
