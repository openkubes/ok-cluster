package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"

	"github.com/openkubes/ok-cluster/internal/runner"
)

var prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
	_, receipt, err := runner.LoadFullRunExecutionManifest(path)
	return receipt, err
}

// runClusterStageRunFullPrepare verifies the complete private first-run
// contract offline. It deliberately has no execute sibling until the binary
// contains one concrete, fixed Platform capability adapter.
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
