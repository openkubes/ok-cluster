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
	IdentityPath, ExpectedIdentityDigest           string
	CollectorEndpoint, CollectorToken, CollectorCA string
	CollectorCADigest                              string
	ValidFor, Timeout                              time.Duration
}

var produceIndependentObservabilityEvidence = func(ctx context.Context, config observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
	identity, err := runner.LoadObservabilityIndependentEvidenceIdentity(config.IdentityPath, config.ExpectedIdentityDigest)
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
	expectedIdentityDigest := flags.String("expected-identity-digest", "", "exact private evidence identity digest")
	collectorEndpoint := flags.String("collector-endpoint", "", "exact HTTPS independent-evidence authority endpoint")
	collectorToken := flags.String("collector-token-file", "", "bounded evidence-authority bearer token file")
	collectorCA := flags.String("collector-ca-file", "", "bounded evidence-authority CA file")
	collectorCADigest := flags.String("collector-ca-digest", "", "expected evidence-authority CA digest")
	validFor := flags.Duration("valid-for", 0, "signed evidence validity, from 1m through 30m")
	timeout := flags.Duration("timeout", 0, "single collection timeout, from 1s through 30m")
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
	if *outputPath == "" || *privateKeyPath == "" || *identityPath == "" || !sha256DigestPattern.MatchString(*expectedIdentityDigest) ||
		*collectorEndpoint == "" || *collectorToken == "" || *collectorCA == "" ||
		!sha256DigestPattern.MatchString(*collectorCADigest) || *validFor < time.Minute || *validFor > 30*time.Minute ||
		*timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("independent Observability evidence production input is incomplete")
	}
	config := observabilityEvidenceProductionConfig{
		OutputPath: *outputPath, PrivateKeyPath: *privateKeyPath,
		IdentityPath: *identityPath, ExpectedIdentityDigest: *expectedIdentityDigest,
		CollectorEndpoint: *collectorEndpoint, CollectorToken: *collectorToken, CollectorCA: *collectorCA,
		CollectorCADigest: *collectorCADigest, ValidFor: *validFor, Timeout: *timeout,
	}
	bounded, cancel := context.WithTimeout(ctx, *timeout+observabilityEvidenceProductionOverhead)
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
