package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

var prepareAggregateEvidenceStageLaunch = func(config runner.AggregateEvidenceStageLaunchMaterialConfig) (aggregateEvidenceLaunchPreparation, error) {
	material, err := runner.BuildAggregateEvidenceStageLaunchMaterial(config)
	if err != nil {
		return aggregateEvidenceLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return aggregateEvidenceLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return aggregateEvidenceLaunchPreparation{}, err
	}
	return aggregateEvidenceLaunchPreparation{
		Format: "ok147-aggregate-evidence-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var executeAggregateEvidenceStageLaunch = func(ctx context.Context, config runner.AggregateEvidenceStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.AggregateEvidenceStageLaunchReceipt, error) {
	material, err := runner.BuildAggregateEvidenceStageLaunchMaterial(config)
	if err != nil {
		return runner.AggregateEvidenceStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.AggregateEvidenceStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.AggregateEvidenceStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.AggregateEvidenceStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type aggregateEvidenceLaunchPreparation struct {
	Format          string                                              `json:"format"`
	State           string                                              `json:"state"`
	Material        runner.AggregateEvidenceStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.AggregateEvidenceStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                                `json:"mutationAllowed"`
}

type aggregateEvidenceLaunchMaterialFlags struct {
	resume *stageResumeFlags

	aggregateProfile, aggregateProfileDigest *string
	networkProfile, networkProfileDigest     *string
	platformProfile, platformProfileDigest   *string
	inputConfigMap                           *string

	jobTemplate, jobTemplateDigest, runID, imageDigest    *string
	ledgerAPIURL, ledgerAPICIDR, ledgerSecret             *string
	managementAPIURL, managementAPICIDR, managementSecret *string
	workloadAPIURL, workloadAPICIDR, workloadSecret       *string
	argoAPIURL, argoAPICIDR, argoSecret                   *string

	runtimeBindingSecret, runtimeBindingMaterial, runtimeBindingReceipt *string
	capabilitySecret, capabilityPath, capabilityDigest                  *string

	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, managementCredential, workloadCredential, argoCredential                   *stageLaunchCredentialFlags
}

func addAggregateEvidenceLaunchMaterialFlags(flags *flag.FlagSet) *aggregateEvidenceLaunchMaterialFlags {
	values := &aggregateEvidenceLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.aggregateProfile = flags.String("aggregate-profile", "", "path to the aggregate evidence profile")
	values.aggregateProfileDigest = flags.String("aggregate-profile-digest", "", "expected aggregate evidence profile digest")
	values.networkProfile = flags.String("network-profile", "", "path to the NetworkReady profile")
	values.networkProfileDigest = flags.String("network-profile-digest", "", "expected NetworkReady profile digest")
	values.platformProfile = flags.String("platform-profile", "", "path to the PlatformReady profile")
	values.platformProfileDigest = flags.String("platform-profile-digest", "", "expected PlatformReady profile digest")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable aggregate evidence input ConfigMap name")
	values.jobTemplate = flags.String("job-template", "", "path to the bounded aggregate-evidence Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected aggregate-evidence Job template digest")
	values.runID = flags.String("run-id", "", "bounded OK-147 aggregate-evidence Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.managementAPIURL = flags.String("management-api-url", "", "exact management observer HTTPS IP endpoint")
	values.managementAPICIDR = flags.String("management-api-cidr", "", "single-address management observer CIDR")
	values.managementSecret = flags.String("management-credential-secret", "", "management observer credential Secret name")
	values.workloadAPIURL = flags.String("workload-api-url", "", "exact workload observer HTTPS IP endpoint")
	values.workloadAPICIDR = flags.String("workload-api-cidr", "", "single-address workload observer CIDR")
	values.workloadSecret = flags.String("workload-credential-secret", "", "workload observer credential Secret name")
	values.argoAPIURL = flags.String("argo-api-url", "", "exact Argo control-plane HTTPS IP endpoint")
	values.argoAPICIDR = flags.String("argo-api-cidr", "", "single-address Argo control-plane CIDR")
	values.argoSecret = flags.String("argo-credential-secret", "", "Argo observer credential Secret name")
	values.runtimeBindingSecret = flags.String("runtime-binding-secret", "", "pre-existing private runtime-binding Secret name")
	values.runtimeBindingMaterial = flags.String("runtime-binding-material", "", "path to private runtime-binding material")
	values.runtimeBindingReceipt = flags.String("runtime-binding-receipt", "", "path to private runtime-binding receipt")
	values.capabilitySecret = flags.String("platform-capability-secret", "", "private platform capability Secret name")
	values.capabilityPath = flags.String("platform-capability", "", "path to private platform capability evidence")
	values.capabilityDigest = flags.String("platform-capability-digest", "", "expected private platform capability evidence digest")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.managementCredential = addStageLaunchCredentialFlags(flags, "management-observer-job", "management observer Job credential")
	values.workloadCredential = addStageLaunchCredentialFlags(flags, "workload-observer-job", "workload observer Job credential")
	values.argoCredential = addStageLaunchCredentialFlags(flags, "argo-observer-job", "Argo observer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *aggregateEvidenceLaunchMaterialFlags) config() (runner.AggregateEvidenceStageLaunchMaterialConfig, error) {
	resume, err := values.resume.config()
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--aggregate-profile", *values.aggregateProfile}, {"--aggregate-profile-digest", *values.aggregateProfileDigest},
		{"--network-profile", *values.networkProfile}, {"--network-profile-digest", *values.networkProfileDigest},
		{"--platform-profile", *values.platformProfile}, {"--platform-profile-digest", *values.platformProfileDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest},
		{"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR}, {"--ledger-credential-secret", *values.ledgerSecret},
		{"--management-api-url", *values.managementAPIURL}, {"--management-api-cidr", *values.managementAPICIDR}, {"--management-credential-secret", *values.managementSecret},
		{"--workload-api-url", *values.workloadAPIURL}, {"--workload-api-cidr", *values.workloadAPICIDR}, {"--workload-credential-secret", *values.workloadSecret},
		{"--argo-api-url", *values.argoAPIURL}, {"--argo-api-cidr", *values.argoAPICIDR}, {"--argo-credential-secret", *values.argoSecret},
		{"--runtime-binding-secret", *values.runtimeBindingSecret}, {"--runtime-binding-material", *values.runtimeBindingMaterial}, {"--runtime-binding-receipt", *values.runtimeBindingReceipt},
		{"--platform-capability-secret", *values.capabilitySecret}, {"--platform-capability", *values.capabilityPath}, {"--platform-capability-digest", *values.capabilityDigest},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest}, {"--runtime-manifest-digest", *values.runtimeManifestDigest},
		{"--installer-api-endpoint", *values.installerAPIEndpoint}, {"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.AggregateEvidenceStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{
		*values.aggregateProfileDigest, *values.networkProfileDigest, *values.platformProfileDigest,
		*values.jobTemplateDigest, *values.capabilityDigest, *values.runtimeManifestDigest,
		*values.installerCADigest, *values.installerTokenDigest, *values.installerEvidence,
	} {
		if !sha256DigestPattern.MatchString(value) {
			return runner.AggregateEvidenceStageLaunchMaterialConfig{}, errors.New("aggregate evidence launch digests must be lowercase SHA-256 identities")
		}
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledger, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, err
	}
	management, err := values.managementCredential.source("management-observer-job")
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, err
	}
	workload, err := values.workloadCredential.source("workload-observer-job")
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, err
	}
	argo, err := values.argoCredential.source("argo-observer-job")
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, fmt.Errorf("read aggregate evidence Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.AggregateEvidenceStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.AggregateEvidenceStageLaunchMaterialConfig{
		Package: runner.AggregateEvidenceStagePackageConfig{
			Input: runner.AggregateEvidenceStageInputConfig{
				Bundle: resume, AggregateEvidenceProfilePath: *values.aggregateProfile,
				ExpectedAggregateProfileDigest: *values.aggregateProfileDigest,
				NetworkProfilePath:             *values.networkProfile, ExpectedNetworkProfileDigest: *values.networkProfileDigest,
				PlatformProfilePath: *values.platformProfile, ExpectedPlatformProfileDigest: *values.platformProfileDigest,
				ConfigMapName: *values.inputConfigMap,
			},
			JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest, RunID: *values.runID, ImageDigest: *values.imageDigest,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerSecret,
			ManagementAPIURL: *values.managementAPIURL, ManagementAPICIDR: *values.managementAPICIDR, ManagementCredentialSecret: *values.managementSecret,
			WorkloadAPIURL: *values.workloadAPIURL, WorkloadAPICIDR: *values.workloadAPICIDR, WorkloadCredentialSecret: *values.workloadSecret,
			ArgoAPIURL: *values.argoAPIURL, ArgoAPICIDR: *values.argoAPICIDR, ArgoCredentialSecret: *values.argoSecret,
			RuntimeBindingSecret: *values.runtimeBindingSecret, RuntimeBindingMaterialPath: *values.runtimeBindingMaterial,
			RuntimeBindingReceiptPath: *values.runtimeBindingReceipt, PlatformCapabilitySecret: *values.capabilitySecret,
			PlatformCapabilityPath: *values.capabilityPath, ExpectedPlatformCapabilityDigest: *values.capabilityDigest,
		},
		MaterializationTime: materializedAt, Ledger: ledger, ManagementObserver: management,
		WorkloadObserver: workload, ArgoObserver: argo,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence,
			PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageRunAggregateEvidenceLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run aggregate-evidence launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addAggregateEvidenceLaunchMaterialFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	preparation, err := prepareAggregateEvidenceStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageRunAggregateEvidenceLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run aggregate-evidence launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addAggregateEvidenceLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use nine-create aggregate evidence launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by aggregate evidence launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("aggregate evidence launch mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-candidate-digest", *expectedCandidateDigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedCandidateDigest) {
		return errors.New("--expected-candidate-digest must be sha256:<64 lowercase hex>")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeAggregateEvidenceStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
		Endpoint: config.Candidate.AuthorityEndpoint, TokenFile: *installerTokenFile,
		CAFile: *installerCAFile, CABundleDigest: config.Candidate.CABundleDigest,
	}, *expectedCandidateDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
}
