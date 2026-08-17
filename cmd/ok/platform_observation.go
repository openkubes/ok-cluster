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

var executePlatformObservationStage = func(ctx context.Context, bundleConfig runner.PlatformObservationStageBundleConfig, fileRuntime runner.PlatformObservationStageFileRuntimeConfig) (execution.ObservationStageRunReceipt, error) {
	bundle, err := runner.LoadPlatformObservationStageBundle(bundleConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	runtimeConfig, err := runner.LoadPlatformObservationStageFileRuntime(fileRuntime)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	opened, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.ObservationStageRunReceipt{}, err
	}
	return opened.Run(ctx)
}

func runClusterStageObservePlatform(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage observe platform", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	execute := flags.Bool("execute", false, "perform exactly the selected read-only platform observation and persist its receipt")
	profilePath := flags.String("platform-profile", "", "path to the immutable PlatformReady profile")
	profileDigest := flags.String("platform-profile-digest", "", "expected PlatformReady profile digest")
	runtimeMaterial := flags.String("runtime-binding-material", "", "path to the private canonical runtime-binding material")
	runtimeReceipt := flags.String("runtime-binding-receipt", "", "path to the verified runtime-binding material receipt")
	capabilityPath := flags.String("platform-capability", "", "path to the redacted platform capability evidence")
	capabilityDigest := flags.String("platform-capability-digest", "", "expected platform capability evidence digest")
	ledgerEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerToken := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCA := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	argoEndpoint := flags.String("argo-api-endpoint", "", "TLS Kubernetes API endpoint for exact Argo Application observation")
	argoToken := flags.String("argo-token-file", "", "path to the short-lived read-only Argo token")
	argoCA := flags.String("argo-ca-file", "", "path to the Argo Kubernetes API CA bundle")
	argoCADigest := flags.String("argo-ca-digest", "", "expected Argo Kubernetes API CA digest")
	pollInterval := flags.Duration("poll-interval", 0, "bounded interval between verified Unknown observations")
	pollTimeout := flags.Duration("poll-timeout", 0, "maximum bounded platform observation duration")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("platform observation requires explicit --execute")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--platform-profile", *profilePath}, {"--platform-profile-digest", *profileDigest},
		{"--runtime-binding-material", *runtimeMaterial}, {"--runtime-binding-receipt", *runtimeReceipt},
		{"--platform-capability", *capabilityPath}, {"--platform-capability-digest", *capabilityDigest},
		{"--ledger-api-endpoint", *ledgerEndpoint}, {"--ledger-token-file", *ledgerToken}, {"--ledger-ca-file", *ledgerCA},
		{"--argo-api-endpoint", *argoEndpoint}, {"--argo-token-file", *argoToken}, {"--argo-ca-file", *argoCA}, {"--argo-ca-digest", *argoCADigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{*profileDigest, *capabilityDigest, *argoCADigest} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("platform observation digests must be lowercase SHA-256 identities")
		}
	}
	if *pollInterval < time.Second || *pollInterval > 5*time.Minute || *pollTimeout < *pollInterval || *pollTimeout > 6*time.Hour {
		return errors.New("--poll-interval and --poll-timeout must define a valid bounded observation of at most 6h")
	}
	loadedProfile, err := runner.LoadPlatformProfileFile(runner.PlatformProfileFileConfig{
		Path: *profilePath, ExpectedProfileDigest: *profileDigest,
		ExpectedIntentRevision: resume.PlanExpected.IntentRevision, ExpectedPlatformRevision: resume.PlanExpected.PlatformRevision,
		ExpectedExecutionFixture: resume.PlanExpected.ExecutionFixture,
	})
	if err != nil {
		return err
	}
	bundleConfig := runner.PlatformObservationStageBundleConfig{
		StageResumeConfig: resume, Profile: loadedProfile.Profile, ExpectedProfileDigest: loadedProfile.Digest,
	}
	fileRuntime := runner.PlatformObservationStageFileRuntimeConfig{
		Bundle: resume, Profile: loadedProfile.Profile,
		Ledger: runner.KubernetesLedgerConfig{Endpoint: *ledgerEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerToken, CAFile: *ledgerCA},
		Argo: runner.KubernetesAuthorityConfig{
			Endpoint: *argoEndpoint, AuthorityIdentity: resume.PlanExpected.GitOpsAuthority,
			TokenFile: *argoToken, CAFile: *argoCA, CABundleDigest: *argoCADigest,
		},
		RuntimeMaterialPath: *runtimeMaterial, RuntimeReceiptPath: *runtimeReceipt,
		CapabilityPath: *capabilityPath, ExpectedCapabilityDigest: *capabilityDigest,
		PollInterval: *pollInterval, PollTimeout: *pollTimeout,
		Clock: func() time.Time { return time.Now().UTC() }, Wait: runner.WaitWithTimer,
	}
	boundedContext, cancel := context.WithTimeout(ctx, *pollTimeout+lifecycleObservationRunOverhead)
	defer cancel()
	receipt, runErr := executePlatformObservationStage(boundedContext, bundleConfig, fileRuntime)
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
