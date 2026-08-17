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

var prepareRuntimeBindingStageLaunch = func(config runner.RuntimeBindingStageLaunchMaterialConfig) (runtimeBindingLaunchPreparation, error) {
	material, err := runner.BuildRuntimeBindingStageLaunchMaterial(config)
	if err != nil {
		return runtimeBindingLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return runtimeBindingLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return runtimeBindingLaunchPreparation{}, err
	}
	return runtimeBindingLaunchPreparation{
		Format: "ok147-runtime-binding-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var executeRuntimeBindingStageLaunch = func(ctx context.Context, config runner.RuntimeBindingStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.RuntimeBindingStageLaunchReceipt, error) {
	material, err := runner.BuildRuntimeBindingStageLaunchMaterial(config)
	if err != nil {
		return runner.RuntimeBindingStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.RuntimeBindingStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.RuntimeBindingStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.RuntimeBindingStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type runtimeBindingLaunchPreparation struct {
	Format          string                                           `json:"format"`
	State           string                                           `json:"state"`
	Material        runner.RuntimeBindingStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.RuntimeBindingStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                             `json:"mutationAllowed"`
}

type runtimeBindingLaunchMaterialFlags struct {
	resume                                                                                       *stageResumeFlags
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                           *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret, persistenceCredentialSecret             *string
	workloadAPIURL, workloadAPICIDR, workloadCredentialSecret, workloadBinding, workloadDigest   *string
	materializedAt, runtimeManifest, runtimeManifestDigest                                       *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt *string
	ledgerCredential, persistenceCredential, workloadCredential                                  *stageLaunchCredentialFlags
}

func addRuntimeBindingLaunchMaterialFlags(flags *flag.FlagSet) *runtimeBindingLaunchMaterialFlags {
	values := &runtimeBindingLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.jobTemplate = flags.String("job-template", "", "path to the bounded runtime-binding Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 runtime-binding Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable runtime-binding input ConfigMap name")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger writer credential Secret name")
	values.persistenceCredentialSecret = flags.String("persistence-credential-secret", "", "runtime-binding persistence writer credential Secret name")
	values.workloadAPIURL = flags.String("workload-api-url", "", "exact workload-observer HTTPS IP endpoint")
	values.workloadAPICIDR = flags.String("workload-api-cidr", "", "single-address workload-observer CIDR")
	values.workloadCredentialSecret = flags.String("workload-credential-secret", "", "workload observer credential Secret name")
	values.workloadBinding = flags.String("workload-binding", "", "path to the private workload-authority binding")
	values.workloadDigest = flags.String("workload-binding-digest", "", "expected workload-authority binding digest")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-writer-job", "ledger writer Job credential")
	values.persistenceCredential = addStageLaunchCredentialFlags(flags, "persistence-writer-job", "persistence writer Job credential")
	values.workloadCredential = addStageLaunchCredentialFlags(flags, "workload-observer-job", "read-only workload observer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected management installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected management installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *runtimeBindingLaunchMaterialFlags) config() (runner.RuntimeBindingStageLaunchMaterialConfig, error) {
	resume, err := values.resume.config()
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest},
		{"--run-id", *values.runID}, {"--image", *values.imageDigest}, {"--input-configmap", *values.inputConfigMap},
		{"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR}, {"--ledger-credential-secret", *values.ledgerCredentialSecret},
		{"--persistence-credential-secret", *values.persistenceCredentialSecret},
		{"--workload-api-url", *values.workloadAPIURL}, {"--workload-api-cidr", *values.workloadAPICIDR}, {"--workload-credential-secret", *values.workloadCredentialSecret},
		{"--workload-binding", *values.workloadBinding}, {"--workload-binding-digest", *values.workloadDigest},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest}, {"--runtime-manifest-digest", *values.runtimeManifestDigest},
		{"--installer-api-endpoint", *values.installerAPIEndpoint}, {"--installer-ca-digest", *values.installerCADigest},
		{"--installer-token-digest", *values.installerTokenDigest}, {"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.RuntimeBindingStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*values.jobTemplateDigest, *values.workloadDigest, *values.runtimeManifestDigest, *values.installerCADigest, *values.installerTokenDigest, *values.installerEvidence} {
		if !sha256DigestPattern.MatchString(value) {
			return runner.RuntimeBindingStageLaunchMaterialConfig{}, errors.New("runtime binding launch digests must be lowercase SHA-256 identities")
		}
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledger, err := values.ledgerCredential.source("ledger-writer-job")
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, err
	}
	persistence, err := values.persistenceCredential.source("persistence-writer-job")
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, err
	}
	workload, err := values.workloadCredential.source("workload-observer-job")
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, err
	}
	if ledger.TokenFile == persistence.TokenFile || ledger.TokenFile == workload.TokenFile || persistence.TokenFile == workload.TokenFile ||
		ledger.TokenDigest == persistence.TokenDigest || ledger.TokenDigest == workload.TokenDigest || persistence.TokenDigest == workload.TokenDigest ||
		*values.ledgerCredentialSecret == *values.persistenceCredentialSecret || *values.ledgerCredentialSecret == *values.workloadCredentialSecret || *values.persistenceCredentialSecret == *values.workloadCredentialSecret {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, errors.New("runtime binding launch requires three distinct credential identities")
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, fmt.Errorf("read runtime binding Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.RuntimeBindingStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	return runner.RuntimeBindingStageLaunchMaterialConfig{
		Package: runner.RuntimeBindingStagePackageConfig{
			Bundle: resume, InputConfigMap: *values.inputConfigMap,
			JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest, RunID: *values.runID, ImageDigest: *values.imageDigest,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			PersistenceCredentialSecret: *values.persistenceCredentialSecret,
			WorkloadAPIURL:              *values.workloadAPIURL, WorkloadAPICIDR: *values.workloadAPICIDR, WorkloadCredentialSecret: *values.workloadCredentialSecret,
			WorkloadBindingPath: *values.workloadBinding, ExpectedWorkloadBindingDigest: *values.workloadDigest,
		},
		MaterializationTime: materializedAt, LedgerWriter: ledger, PersistenceWriter: persistence, WorkloadObserver: workload,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence, PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageBindRuntimeLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage bind runtime launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addRuntimeBindingLaunchMaterialFlags(flags)
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
	preparation, err := prepareRuntimeBindingStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageBindRuntimeLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage bind runtime launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addRuntimeBindingLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use seven-object runtime-binding launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by runtime-binding launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("runtime binding launch mutation requires explicit --execute")
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
	receipt, launchErr := executeRuntimeBindingStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
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
