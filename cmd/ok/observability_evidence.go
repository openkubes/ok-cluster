package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

const observabilityEvidenceProductionOverhead = 10 * time.Second

var (
	observabilityEvidenceRunIDPattern = regexp.MustCompile(`^ok147-[0-9a-f]{24}$`)
	observabilityTargetUIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type observabilityEvidenceProductionConfig struct {
	OutputPath, PrivateKeyPath                     string
	RunID, TargetClusterUID, FixtureDigest         string
	ProfileDigest                                  string
	CollectorEndpoint, CollectorToken, CollectorCA string
	CollectorCADigest                              string
	ValidFor, Timeout                              time.Duration
}

var produceIndependentObservabilityEvidence = func(ctx context.Context, config observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
	profile, err := runner.StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || profile.Digest() != config.ProfileDigest {
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
	return producer.Produce(ctx, runner.ObservabilityCapabilityObservationIdentity{
		RunID: config.RunID, TargetClusterUID: config.TargetClusterUID,
		FixtureDigest: config.FixtureDigest, ProfileDigest: config.ProfileDigest,
	})
}

func runClusterStageEvidenceObservabilityProduce(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability produce", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputPath := flags.String("output", "", "absent private 0600 evidence destination")
	privateKeyPath := flags.String("private-key", "", "private Ed25519 evidence-authority key")
	runID := flags.String("run-id", "", "deterministic OK-147 capability run identity")
	targetClusterUID := flags.String("target-cluster-uid", "", "exact runtime CAPI Cluster UID")
	fixtureDigest := flags.String("fixture-digest", "", "exact synthetic fixture digest")
	profileDigest := flags.String("profile-digest", "", "exact standard Observability profile digest")
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
	if *outputPath == "" || *privateKeyPath == "" || !observabilityEvidenceRunIDPattern.MatchString(*runID) ||
		!observabilityTargetUIDPattern.MatchString(*targetClusterUID) || !sha256DigestPattern.MatchString(*fixtureDigest) ||
		!sha256DigestPattern.MatchString(*profileDigest) || *collectorEndpoint == "" || *collectorToken == "" || *collectorCA == "" ||
		!sha256DigestPattern.MatchString(*collectorCADigest) || *validFor < time.Minute || *validFor > 30*time.Minute ||
		*timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("independent Observability evidence production input is incomplete")
	}
	config := observabilityEvidenceProductionConfig{
		OutputPath: *outputPath, PrivateKeyPath: *privateKeyPath,
		RunID: *runID, TargetClusterUID: *targetClusterUID, FixtureDigest: *fixtureDigest, ProfileDigest: *profileDigest,
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
