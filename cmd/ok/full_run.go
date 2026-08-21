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

const fullRunExecutionTimeout = 3 * time.Hour

type fullRunActivationRunner interface {
	Run(context.Context) (runner.FullRunExecutionActivationReceipt, error)
}

var prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
	_, receipt, err := runner.LoadFullRunExecutionManifest(path)
	return receipt, err
}

var materializeFullRunExecutionBundle = runner.MaterializeFullRunExecutionBundle

var openKubernetesObservabilityFullRunActivation = func(path, publicKeyPath string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
	return runner.OpenKubernetesObservabilityFullRunActivation(path, runner.KubernetesObservabilityFullRunActivationConfig{
		IndependentEvidencePublicKeyPath: publicKeyPath, Clock: time.Now, Wait: runner.WaitWithTimer,
	})
}

// runClusterStageRunFullPrepare verifies the complete private first-run
// contract offline and emits the identity required by the separate execute
// command. It opens no credential or runtime dependency.
func runClusterStageRunFullPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the private 0600 full-run execution manifest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *manifestPath == "" {
		return errors.New("--manifest is required")
	}
	manifest, err := prepareFullRunExecutionManifest(*manifestPath)
	if err != nil {
		return err
	}
	if manifest.Format != runner.FullRunExecutionManifestReceiptFormat || manifest.State != "VERIFIED" || manifest.MutationAllowed {
		return errors.New("full-run manifest preparation did not verify")
	}
	receipt := runner.FullRunExecutionActivationReceipt{
		Format: runner.FullRunExecutionActivationReceiptFormat, State: "PREPARED", Manifest: manifest,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStageRunFullMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "projected immutable full-run bundle directory")
	destination := flags.String("destination", "", "fixed private executor workspace")
	handoff := flags.String("handoff", "", "fixed private evidence-authority handoff")
	expectedBundleDigest := flags.String("expected-bundle-digest", "", "exact canonical bundle index digest")
	materialize := flags.Bool("materialize", false, "create the private full-run workspace")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*materialize {
		return errors.New("full-run private materialization requires explicit --materialize")
	}
	if *source == "" || *destination == "" || *handoff == "" || !sha256DigestPattern.MatchString(*expectedBundleDigest) {
		return errors.New("--source, --destination, --handoff and a lowercase SHA-256 --expected-bundle-digest are required")
	}
	receipt, err := materializeFullRunExecutionBundle(runner.FullRunExecutionBundleMaterializationConfig{
		SourceDirectory: *source, DestinationDirectory: *destination, HandoffDirectory: *handoff,
		ExpectedBundleDigest: *expectedBundleDigest,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if outputErr := encoder.Encode(receipt); outputErr != nil {
		return outputErr
	}
	return err
}

func runClusterStageRunFullExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the private 0600 full-run execution manifest")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact semantic digest emitted by prepare")
	evidencePublicKey := flags.String("independent-evidence-public-key", "", "pinned independent Observability evidence public key")
	execute := flags.Bool("execute", false, "perform the exact single-use Stage 1-12 full run")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("full-run mutation requires explicit --execute")
	}
	if *manifestPath == "" || *evidencePublicKey == "" || !sha256DigestPattern.MatchString(*expectedManifestDigest) {
		return errors.New("--manifest, --independent-evidence-public-key and a lowercase SHA-256 --expected-manifest-digest are required")
	}
	verified, err := prepareFullRunExecutionManifest(*manifestPath)
	if err != nil || verified.Format != runner.FullRunExecutionManifestReceiptFormat || verified.State != "VERIFIED" ||
		verified.MutationAllowed || verified.ManifestDigest != *expectedManifestDigest {
		return errors.New("full-run manifest differs from the prepared identity")
	}
	activation, prepared, err := openKubernetesObservabilityFullRunActivation(*manifestPath, *evidencePublicKey)
	if err != nil {
		return err
	}
	if activation == nil || prepared.Format != runner.FullRunExecutionActivationReceiptFormat || prepared.State != "PREPARED" ||
		prepared.Execution != nil || prepared.Manifest.State != "VERIFIED" || prepared.Manifest.MutationAllowed ||
		prepared.Manifest != verified {
		return errors.New("full-run manifest differs from the prepared identity")
	}
	bounded, cancel := context.WithTimeout(ctx, fullRunExecutionTimeout)
	defer cancel()
	receipt, runErr := activation.Run(bounded)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	return runErr
}
