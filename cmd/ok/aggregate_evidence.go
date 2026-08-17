package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/runner"
)

var executeAggregateEvidenceStage = func(ctx context.Context, bundleConfig runner.AggregateEvidenceStageBundleConfig, fileRuntime runner.AggregateEvidenceStageFileRuntimeConfig) (execution.EvaluationStageRunReceipt, error) {
	bundle, err := runner.LoadAggregateEvidenceStageBundle(bundleConfig)
	if err != nil {
		return execution.EvaluationStageRunReceipt{}, err
	}
	runtimeConfig, err := runner.LoadAggregateEvidenceStageFileRuntime(fileRuntime)
	if err != nil {
		return execution.EvaluationStageRunReceipt{}, err
	}
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.EvaluationStageRunReceipt{}, err
	}
	return opened.Run(ctx)
}

func runClusterStageEvaluateAggregate(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evaluate aggregate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact read-only aggregate evaluation and persist its receipt")
	aggregateProfile := flags.String("aggregate-profile", "", "path to the aggregate evidence profile")
	aggregateProfileDigest := flags.String("aggregate-profile-digest", "", "expected aggregate evidence profile digest")
	networkProfile := flags.String("network-profile", "", "path to the NetworkReady profile")
	networkProfileDigest := flags.String("network-profile-digest", "", "expected NetworkReady profile digest")
	platformProfile := flags.String("platform-profile", "", "path to the PlatformReady profile")
	platformProfileDigest := flags.String("platform-profile-digest", "", "expected PlatformReady profile digest")
	runtimeBinding := flags.String("runtime-binding", "", "path to private canonical runtime-binding material")
	runtimeBindingReceipt := flags.String("runtime-binding-receipt", "", "path to the verified runtime-binding material receipt")
	platformCapability := flags.String("platform-capability", "", "path to private platform capability evidence")
	platformCapabilityDigest := flags.String("platform-capability-digest", "", "expected platform capability evidence digest")
	ledgerEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerToken := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCA := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	managementEndpoint := flags.String("management-api-endpoint", "", "TLS Kubernetes API endpoint for exact CAPI and HCP/HRP reads")
	managementToken := flags.String("management-token-file", "", "path to the short-lived management observer token")
	managementCA := flags.String("management-ca-file", "", "path to the management Kubernetes API CA bundle")
	workloadEndpoint := flags.String("workload-api-endpoint", "", "expected runtime-bound workload Kubernetes API endpoint")
	workloadToken := flags.String("workload-token-file", "", "path to the short-lived workload observer token")
	workloadCA := flags.String("workload-ca-file", "", "path to the workload Kubernetes API CA bundle")
	argoEndpoint := flags.String("argo-api-endpoint", "", "TLS Kubernetes API endpoint for exact Argo Application reads")
	argoToken := flags.String("argo-token-file", "", "path to the short-lived Argo observer token")
	argoCA := flags.String("argo-ca-file", "", "path to the Argo Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("aggregate evidence evaluation requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--aggregate-profile", *aggregateProfile}, {"--aggregate-profile-digest", *aggregateProfileDigest},
		{"--network-profile", *networkProfile}, {"--network-profile-digest", *networkProfileDigest},
		{"--platform-profile", *platformProfile}, {"--platform-profile-digest", *platformProfileDigest},
		{"--runtime-binding", *runtimeBinding}, {"--runtime-binding-receipt", *runtimeBindingReceipt},
		{"--platform-capability", *platformCapability}, {"--platform-capability-digest", *platformCapabilityDigest},
		{"--ledger-api-endpoint", *ledgerEndpoint}, {"--ledger-token-file", *ledgerToken}, {"--ledger-ca-file", *ledgerCA},
		{"--management-api-endpoint", *managementEndpoint}, {"--management-token-file", *managementToken}, {"--management-ca-file", *managementCA},
		{"--workload-api-endpoint", *workloadEndpoint}, {"--workload-token-file", *workloadToken}, {"--workload-ca-file", *workloadCA},
		{"--argo-api-endpoint", *argoEndpoint}, {"--argo-token-file", *argoToken}, {"--argo-ca-file", *argoCA},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*aggregateProfileDigest, *networkProfileDigest, *platformProfileDigest, *platformCapabilityDigest} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("aggregate evidence digests must be lowercase SHA-256 identities")
		}
	}
	loadedAggregate, err := runner.LoadAggregateEvidenceProfileFile(runner.AggregateEvidenceProfileFileConfig{
		Path: *aggregateProfile, ExpectedProfileDigest: *aggregateProfileDigest,
		ExpectedIntentRevision: resume.PlanExpected.IntentRevision, ExpectedEnablementRevision: resume.PlanExpected.EnablementRevision,
		ExpectedPlatformRevision: resume.PlanExpected.PlatformRevision, ExpectedExecutionFixture: resume.PlanExpected.ExecutionFixture,
	})
	if err != nil {
		return err
	}
	loadedNetwork, err := runner.LoadNetworkProfileFile(runner.NetworkProfileFileConfig{
		Path: *networkProfile, ExpectedProfileDigest: *networkProfileDigest,
		ExpectedIntentRevision: resume.PlanExpected.IntentRevision, ExpectedEnablementRevision: resume.PlanExpected.EnablementRevision,
	})
	if err != nil {
		return err
	}
	loadedPlatform, err := runner.LoadPlatformProfileFile(runner.PlatformProfileFileConfig{
		Path: *platformProfile, ExpectedProfileDigest: *platformProfileDigest,
		ExpectedIntentRevision: resume.PlanExpected.IntentRevision, ExpectedPlatformRevision: resume.PlanExpected.PlatformRevision,
		ExpectedExecutionFixture: resume.PlanExpected.ExecutionFixture,
	})
	if err != nil {
		return err
	}
	bundleConfig := runner.AggregateEvidenceStageBundleConfig{
		StageResumeConfig: resume, Profile: loadedAggregate.Profile, ExpectedProfileDigest: loadedAggregate.Digest,
	}
	fileRuntime := runner.AggregateEvidenceStageFileRuntimeConfig{
		Bundle: resume, NetworkProfile: loadedNetwork.Profile, PlatformProfile: loadedPlatform.Profile,
		Ledger: runner.KubernetesLedgerConfig{Endpoint: *ledgerEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerToken, CAFile: *ledgerCA},
		Management: runner.KubernetesAuthorityConfig{
			Endpoint: *managementEndpoint, AuthorityIdentity: resume.PlanExpected.ManagementAuthority,
			TokenFile: *managementToken, CAFile: *managementCA,
		},
		Argo: runner.KubernetesAuthorityConfig{
			Endpoint: *argoEndpoint, AuthorityIdentity: resume.PlanExpected.GitOpsAuthority,
			TokenFile: *argoToken, CAFile: *argoCA,
		},
		ExpectedWorkloadEndpoint: *workloadEndpoint, WorkloadTokenFile: *workloadToken, WorkloadCAFile: *workloadCA,
		RuntimeMaterialPath: *runtimeBinding, RuntimeReceiptPath: *runtimeBindingReceipt,
		CapabilityPath: *platformCapability, ExpectedCapabilityDigest: *platformCapabilityDigest,
		Clock: func() time.Time { return time.Now().UTC() },
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executeAggregateEvidenceStage(boundedContext, bundleConfig, fileRuntime)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}
