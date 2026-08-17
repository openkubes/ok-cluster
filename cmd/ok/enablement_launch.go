package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
)

var prepareEnablementStageLaunch = func(config runner.EnablementStageLaunchMaterialConfig) (enablementLaunchPreparation, error) {
	material, err := runner.BuildEnablementStageLaunchMaterial(config)
	if err != nil {
		return enablementLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return enablementLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return enablementLaunchPreparation{}, err
	}
	return enablementLaunchPreparation{
		Format: "ok147-enablement-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var executeEnablementStageLaunch = func(ctx context.Context, config runner.EnablementStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.EnablementStageLaunchReceipt, error) {
	material, err := runner.BuildEnablementStageLaunchMaterial(config)
	if err != nil {
		return runner.EnablementStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.EnablementStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.EnablementStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.EnablementStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type enablementLaunchPreparation struct {
	Format          string                                       `json:"format"`
	State           string                                       `json:"state"`
	Material        runner.EnablementStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.EnablementStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                         `json:"mutationAllowed"`
}

type enablementLaunchMaterialFlags struct {
	resume                                                                                       *stageResumeFlags
	grantPath, grantKeyPath, evaluationTime, artifactPath, objectName                            *string
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                           *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret                                          *string
	managementAPIURL, managementAPICIDR, managementCredentialSecret                              *string
	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, managementCredential                                                       *stageLaunchCredentialFlags
}

func addEnablementLaunchMaterialFlags(flags *flag.FlagSet) *enablementLaunchMaterialFlags {
	values := &enablementLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.grantPath = flags.String("grant", "", "path to the signed single-stage grant")
	values.grantKeyPath = flags.String("grant-key", "", "path to the trusted stage-authority public key")
	values.evaluationTime = flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	values.artifactPath = flags.String("enablement-artifact", "", "path to the exact externally rendered HelmChartProxy")
	values.objectName = flags.String("helmchartproxy-name", "", "independently expected HelmChartProxy name")
	values.jobTemplate = flags.String("job-template", "", "path to the bounded enablement Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 enablement Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable enablement input ConfigMap name")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.managementAPIURL = flags.String("management-api-url", "", "exact management-writer HTTPS IP endpoint")
	values.managementAPICIDR = flags.String("management-api-cidr", "", "single-address management-writer CIDR")
	values.managementCredentialSecret = flags.String("management-credential-secret", "", "management writer credential Secret name")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.managementCredential = addStageLaunchCredentialFlags(flags, "management-writer-job", "management writer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *enablementLaunchMaterialFlags) config() (runner.EnablementStageLaunchMaterialConfig, error) {
	resume, err := values.resume.config()
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *values.grantPath}, {"--grant-key", *values.grantKeyPath}, {"--evaluation-time", *values.evaluationTime},
		{"--enablement-artifact", *values.artifactPath}, {"--helmchartproxy-name", *values.objectName},
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR},
		{"--ledger-credential-secret", *values.ledgerCredentialSecret}, {"--management-api-url", *values.managementAPIURL},
		{"--management-api-cidr", *values.managementAPICIDR}, {"--management-credential-secret", *values.managementCredentialSecret},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest},
		{"--runtime-manifest-digest", *values.runtimeManifestDigest}, {"--installer-api-endpoint", *values.installerAPIEndpoint},
		{"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	evaluatedAt, err := time.Parse(time.RFC3339, *values.evaluationTime)
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("parse evaluation time: %w", err)
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, err
	}
	managementSource, err := values.managementCredential.source("management-writer-job")
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("read enablement Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.EnablementStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.EnablementStageLaunchMaterialConfig{
		Package: runner.EnablementStagePackageConfig{
			Bundle: runner.EnablementStageBundleConfig{
				PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: *values.grantPath, GrantPublicKeyPath: *values.grantKeyPath, EvaluationTime: evaluatedAt,
				ArtifactPath: *values.artifactPath,
				ExpectedObject: projection.ResourceIdentity{
					APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy",
					Namespace: resume.PlanExpected.ContractIdentity.Namespace, Name: *values.objectName,
				},
			},
			JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest,
			RunID: *values.runID, ImageDigest: *values.imageDigest, InputConfigMap: *values.inputConfigMap, HelmChartProxyName: *values.objectName,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			ManagementAPIURL: *values.managementAPIURL, ManagementAPICIDR: *values.managementAPICIDR, ManagementCredentialSecret: *values.managementCredentialSecret,
		},
		MaterializationTime: materializedAt, Ledger: ledgerSource, ManagementWriter: managementSource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence,
			PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageRunEnablementLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run enablement launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addEnablementLaunchMaterialFlags(flags)
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
	preparation, err := prepareEnablementStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageRunEnablementLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run enablement launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addEnablementLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use six-object Enablement launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by Enablement launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("enablement launch mutation requires explicit --execute")
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
	receipt, launchErr := executeEnablementStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
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
