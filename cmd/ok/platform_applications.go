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
	"github.com/openkubes/ok-cluster/internal/submission"
)

var executePlatformApplicationsStage = func(ctx context.Context, bundleConfig runner.PlatformApplicationsStageBundleConfig, runtimeConfig runner.PlatformApplicationsStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
	bundle, err := runner.LoadPlatformApplicationsStageBundle(bundleConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	stage, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	return stage.Run(ctx)
}

func runClusterStageRunPlatformApplications(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run platform-applications", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grant := flags.String("grant", "", "path to the signed platform-applications grant")
	grantKey := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifact := flags.String("platform-applications-artifact", "", "path to the exact externally rendered three-Application artifact")
	artifactDigest := flags.String("platform-applications-digest", "", "expected platform Applications artifact digest")
	profilePath := flags.String("platform-profile", "", "path to the immutable PlatformReady profile")
	profileDigest := flags.String("platform-profile-digest", "", "expected PlatformReady profile digest")
	targetIdentity := flags.String("target-identity-digest", "", "expected immutable workload target identity digest")
	argoNamespace := flags.String("argo-namespace", "", "expected Argo namespace")
	projectName := flags.String("project-name", "", "expected Argo AppProject name")
	registrationName := flags.String("registration-name", "", "expected Argo target registration name")
	sourceRepository := flags.String("source-repository", "", "expected immutable Platform source repository")
	ledgerEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerToken := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCA := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	gitopsEndpoint := flags.String("gitops-api-endpoint", "", "TLS Kubernetes API endpoint for the GitOps writer")
	gitopsToken := flags.String("gitops-token-file", "", "path to the short-lived GitOps writer token")
	gitopsCA := flags.String("gitops-ca-file", "", "path to the GitOps Kubernetes API CA bundle")
	gitopsCADigest := flags.String("gitops-ca-digest", "", "expected GitOps API CA digest")
	execute := flags.Bool("execute", false, "claim and execute exactly the platform-applications stage")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("platform-applications mutation requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *grant}, {"--grant-key", *grantKey}, {"--evaluation-time", *evaluationTime},
		{"--platform-applications-artifact", *artifact}, {"--platform-applications-digest", *artifactDigest},
		{"--platform-profile", *profilePath}, {"--platform-profile-digest", *profileDigest}, {"--target-identity-digest", *targetIdentity},
		{"--argo-namespace", *argoNamespace}, {"--project-name", *projectName}, {"--registration-name", *registrationName}, {"--source-repository", *sourceRepository},
		{"--ledger-api-endpoint", *ledgerEndpoint}, {"--ledger-token-file", *ledgerToken}, {"--ledger-ca-file", *ledgerCA},
		{"--gitops-api-endpoint", *gitopsEndpoint}, {"--gitops-token-file", *gitopsToken}, {"--gitops-ca-file", *gitopsCA}, {"--gitops-ca-digest", *gitopsCADigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*artifactDigest, *profileDigest, *targetIdentity, *gitopsCADigest} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("platform-applications digests must be lowercase SHA-256 identities")
		}
	}
	at, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	loadedProfile, err := runner.LoadPlatformProfileFile(runner.PlatformProfileFileConfig{
		Path: *profilePath, ExpectedProfileDigest: *profileDigest,
		ExpectedIntentRevision: resume.PlanExpected.IntentRevision, ExpectedPlatformRevision: resume.PlanExpected.PlatformRevision,
		ExpectedExecutionFixture: resume.PlanExpected.ExecutionFixture,
	})
	if err != nil {
		return err
	}
	bundleConfig := runner.PlatformApplicationsStageBundleConfig{
		PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
		GrantPath: *grant, GrantPublicKeyPath: *grantKey, EvaluationTime: at, ArtifactPath: *artifact,
		Expected: submission.PlatformApplicationsExpected{
			ArtifactDigest: *artifactDigest, ContractIdentity: resume.PlanExpected.ContractIdentity,
			IntentRevision: resume.PlanExpected.IntentRevision, PlatformRevision: resume.PlanExpected.PlatformRevision,
			ExecutionFixture: resume.PlanExpected.ExecutionFixture, TargetIdentityDigest: *targetIdentity,
			ArgoAuthority: resume.PlanExpected.GitOpsAuthority, ArgoNamespace: *argoNamespace,
			ProjectName: *projectName, RegistrationName: *registrationName, SourceRepository: *sourceRepository,
			Profile: loadedProfile.Profile,
		},
	}
	runtimeConfig := runner.PlatformApplicationsStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{Endpoint: *ledgerEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerToken, CAFile: *ledgerCA},
		GitOps: runner.KubernetesAuthorityConfig{
			Endpoint: *gitopsEndpoint, AuthorityIdentity: resume.PlanExpected.GitOpsAuthority,
			TokenFile: *gitopsToken, CAFile: *gitopsCA, CABundleDigest: *gitopsCADigest,
		},
		Clock: func() time.Time { return time.Now().UTC() },
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executePlatformApplicationsStage(boundedContext, bundleConfig, runtimeConfig)
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
