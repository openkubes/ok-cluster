package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

const observabilityEvidenceProductionOverhead = 10 * time.Second

type observabilityEvidenceProductionConfig struct {
	OutputPath, PrivateKeyPath                     string
	IdentityPath, IdentityReceiptPath              string
	ExpectedManifestDigest                         string
	CollectorEndpoint, CollectorToken, CollectorCA string
	CollectorCADigest                              string
	IdentityPollInterval, IdentityWaitTimeout      time.Duration
	ValidFor, Timeout                              time.Duration
}

type observabilityEvidenceAuthorityRunner interface {
	Run(context.Context) (runner.ObservabilityIndependentEvidenceReceipt, error)
}

var openObservabilityEvidenceAuthorityActivation = func(path string) (observabilityEvidenceAuthorityRunner, error) {
	return runner.OpenObservabilityEvidenceAuthorityActivation(path, runner.ObservabilityEvidenceAuthorityActivationRuntime{
		Clock: time.Now, Wait: runner.WaitWithTimer,
	})
}

var produceIndependentObservabilityEvidence = func(ctx context.Context, config observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
	identity, err := runner.WaitForObservabilityIndependentEvidenceIdentity(ctx, runner.ObservabilityIndependentEvidenceIdentityWaitConfig{
		IdentityPath: config.IdentityPath, ReceiptPath: config.IdentityReceiptPath,
		ExpectedManifestDigest: config.ExpectedManifestDigest, PollInterval: config.IdentityPollInterval,
		Timeout: config.IdentityWaitTimeout, Wait: runner.WaitWithTimer,
	})
	if err != nil {
		return runner.ObservabilityIndependentEvidenceReceipt{}, errors.New("load runtime-bound observability evidence identity")
	}
	profile, err := runner.StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || profile.Digest() != identity.ProfileDigest {
		return runner.ObservabilityIndependentEvidenceReceipt{}, errors.New("observability evidence profile differs from standard")
	}
	collector, err := runner.OpenHTTPObservabilityIndependentEvidenceCollector(runner.HTTPObservabilityIndependentEvidenceCollectorConfig{
		Endpoint: config.CollectorEndpoint, TokenFile: config.CollectorToken,
		CAFile: config.CollectorCA, CABundleDigest: config.CollectorCADigest,
	})
	if err != nil {
		return runner.ObservabilityIndependentEvidenceReceipt{}, errors.New("open bounded observability evidence collector")
	}
	producer, err := runner.OpenObservabilityIndependentEvidenceProducer(runner.ObservabilityIndependentEvidenceProducerConfig{
		OutputPath: config.OutputPath, PrivateKeyPath: config.PrivateKeyPath,
		Profile: profile, ValidFor: config.ValidFor, Timeout: config.Timeout, Clock: time.Now, Collector: collector,
	})
	if err != nil {
		return runner.ObservabilityIndependentEvidenceReceipt{}, errors.New("open bounded observability evidence producer")
	}
	return producer.Produce(ctx, identity)
}

var materializeObservabilityEvidenceIdentity = runner.MaterializeObservabilityIndependentEvidenceIdentity
var materializeObservabilityEvidenceAuthority = runner.MaterializeObservabilityEvidenceAuthority

func runClusterStageEvidenceObservabilityAuthorityMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability authority materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "projected immutable evidence-authority Secret directory")
	destination := flags.String("destination", "", "fixed private evidence-authority directory")
	activationDigest := flags.String("expected-activation-digest", "", "exact canonical evidence-authority activation digest")
	evidenceKeyID := flags.String("expected-evidence-key-id", "", "exact Ed25519 evidence public-key identity")
	collectorCADigest := flags.String("expected-collector-ca-digest", "", "exact collector CA identity")
	materialize := flags.Bool("materialize", false, "create the private regular-file authority directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*materialize || *source == "" || *destination == "" ||
		!sha256DigestPattern.MatchString(*activationDigest) || !sha256DigestPattern.MatchString(*evidenceKeyID) ||
		!sha256DigestPattern.MatchString(*collectorCADigest) {
		return errors.New("observability evidence authority materialization input is incomplete")
	}
	receipt, err := materializeObservabilityEvidenceAuthority(runner.ObservabilityEvidenceAuthorityMaterializationConfig{
		SourceDirectory: *source, DestinationDirectory: *destination,
		ExpectedActivationDigest: *activationDigest, ExpectedEvidenceKeyID: *evidenceKeyID,
		ExpectedCollectorCADigest: *collectorCADigest,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(receipt); encodeErr != nil {
		return encodeErr
	}
	return err
}

func runClusterStageEvidenceObservabilityIdentityMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability identity materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "private full-run execution manifest")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact verified full-run manifest digest")
	receiptPrefixPath := flags.String("receipt-prefix", "", "exact six-stage receipt-prefix manifest")
	expectedReceiptPrefixDigest := flags.String("expected-receipt-prefix-digest", "", "exact six-stage receipt-prefix digest")
	outputPath := flags.String("output", "", "absent private 0600 evidence identity destination")
	materialize := flags.Bool("materialize", false, "create exactly one private evidence identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*materialize || *manifestPath == "" || *receiptPrefixPath == "" || *outputPath == "" ||
		!sha256DigestPattern.MatchString(*expectedManifestDigest) || !sha256DigestPattern.MatchString(*expectedReceiptPrefixDigest) {
		return errors.New("observability evidence identity materialization input is incomplete")
	}
	receipt, err := materializeObservabilityEvidenceIdentity(runner.ObservabilityIndependentEvidenceIdentityMaterialConfig{
		ManifestPath: *manifestPath, ExpectedManifestDigest: *expectedManifestDigest,
		ReceiptPrefixPath: *receiptPrefixPath, ExpectedReceiptPrefixDigest: *expectedReceiptPrefixDigest,
		OutputPath: *outputPath,
	})
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(receipt); encodeErr != nil {
			return encodeErr
		}
	}
	return err
}

func runClusterStageEvidenceObservabilityProduce(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability produce", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("output", "", "absent private 0600 evidence destination")
	privateKeyPath := flags.String("private-key", "", "private Ed25519 evidence-authority key")
	identityPath := flags.String("identity-file", "", "private runtime-bound evidence identity")
	identityReceiptPath := flags.String("identity-receipt-file", "", "redaction-safe runtime-bound evidence identity receipt")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact full-run manifest digest")
	identityPollInterval := flags.Duration("identity-poll-interval", 0, "private identity receipt polling interval")
	identityWaitTimeout := flags.Duration("identity-wait-timeout", 0, "bounded private identity receipt wait")
	collectorEndpoint := flags.String("collector-endpoint", "", "exact HTTPS independent-evidence authority endpoint")
	collectorToken := flags.String("collector-token-file", "", "bounded evidence-authority bearer token file")
	collectorCA := flags.String("collector-ca-file", "", "bounded evidence-authority CA file")
	collectorCADigest := flags.String("collector-ca-digest", "", "expected evidence-authority CA digest")
	validFor := flags.Duration("valid-for", 0, "signed evidence validity, from 1m through 30m")
	timeout := flags.Duration("timeout", 0, "single collection timeout, from 1s through 30m")
	activationPath := flags.String("activation", "", "canonical private evidence-authority activation")
	produce := flags.Bool("produce", false, "perform one independent collection and create-only signed evidence write")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*produce {
		return errors.New("independent Observability evidence production requires explicit --produce")
	}
	if *activationPath != "" {
		if *outputPath != "" || *privateKeyPath != "" || *identityPath != "" || *identityReceiptPath != "" || *expectedManifestDigest != "" ||
			*identityPollInterval != 0 || *identityWaitTimeout != 0 || *collectorEndpoint != "" || *collectorToken != "" || *collectorCA != "" ||
			*collectorCADigest != "" || *validFor != 0 || *timeout != 0 {
			return errors.New("evidence-authority activation cannot be combined with individual production flags")
		}
		execution, err := openObservabilityEvidenceAuthorityActivation(*activationPath)
		if err != nil {
			return err
		}
		receipt, runErr := execution.Run(ctx)
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
	if *outputPath == "" || *privateKeyPath == "" || *identityPath == "" || *identityReceiptPath == "" ||
		!sha256DigestPattern.MatchString(*expectedManifestDigest) || *identityPollInterval < time.Millisecond || *identityPollInterval > 30*time.Second ||
		*identityWaitTimeout < time.Second || *identityWaitTimeout > fullRunExecutionTimeout ||
		*collectorEndpoint == "" || *collectorToken == "" || *collectorCA == "" ||
		!sha256DigestPattern.MatchString(*collectorCADigest) || *validFor < time.Minute || *validFor > 30*time.Minute ||
		*timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("independent Observability evidence production input is incomplete")
	}
	config := observabilityEvidenceProductionConfig{
		OutputPath: *outputPath, PrivateKeyPath: *privateKeyPath,
		IdentityPath: *identityPath, IdentityReceiptPath: *identityReceiptPath, ExpectedManifestDigest: *expectedManifestDigest,
		IdentityPollInterval: *identityPollInterval, IdentityWaitTimeout: *identityWaitTimeout,
		CollectorEndpoint: *collectorEndpoint, CollectorToken: *collectorToken, CollectorCA: *collectorCA,
		CollectorCADigest: *collectorCADigest, ValidFor: *validFor, Timeout: *timeout,
	}
	bounded, cancel := context.WithTimeout(ctx, *identityWaitTimeout+*timeout+observabilityEvidenceProductionOverhead)
	defer cancel()
	receipt, produceErr := produceIndependentObservabilityEvidence(bounded, config)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return produceErr
}
