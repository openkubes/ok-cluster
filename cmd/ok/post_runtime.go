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

const (
	postRuntimeCLIReceiptFormat = "ok147-post-runtime-cli-receipt/v1"
	postRuntimeExecutionTimeout = 3 * time.Hour
)

type postRuntimeExecutor interface {
	Run(context.Context) (runner.PostRuntimeExecutionReceipt, error)
}

var openPostRuntimeExecutor = func(path string) (postRuntimeExecutor, runner.PostRuntimeExecutionManifestReceipt, error) {
	return runner.OpenPostRuntimeExecutionManifest(path)
}

type postRuntimeCLIReceipt struct {
	Format    string                                     `json:"format"`
	State     string                                     `json:"state"`
	Manifest  runner.PostRuntimeExecutionManifestReceipt `json:"manifest"`
	Execution *runner.PostRuntimeExecutionReceipt        `json:"execution,omitempty"`
}

func runClusterStageRunPostRuntimePrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the private 0600 post-runtime execution manifest")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *manifestPath == "" {
		return errors.New("--manifest is required")
	}
	_, receipt, err := openPostRuntimeExecutor(*manifestPath)
	if err != nil {
		return err
	}
	return writePostRuntimeCLIReceipt(stdout, postRuntimeCLIReceipt{
		Format: postRuntimeCLIReceiptFormat, State: "PREPARED", Manifest: receipt,
	})
}

func runClusterStageRunPostRuntimeExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "path to the private 0600 post-runtime execution manifest")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact semantic digest emitted by prepare")
	execute := flags.Bool("execute", false, "perform the exact single-use Stage 8-12 execution suffix")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("post-runtime mutation requires explicit --execute")
	}
	if *manifestPath == "" || !sha256DigestPattern.MatchString(*expectedManifestDigest) {
		return errors.New("--manifest and a lowercase SHA-256 --expected-manifest-digest are required")
	}
	executor, manifestReceipt, err := openPostRuntimeExecutor(*manifestPath)
	if err != nil {
		return err
	}
	if executor == nil || manifestReceipt.State != "VERIFIED" || manifestReceipt.MutationAllowed || manifestReceipt.ManifestDigest != *expectedManifestDigest {
		return errors.New("post-runtime manifest differs from the prepared identity")
	}
	bounded, cancel := context.WithTimeout(ctx, postRuntimeExecutionTimeout)
	defer cancel()
	executionReceipt, runErr := executor.Run(bounded)
	outputErr := writePostRuntimeCLIReceipt(stdout, postRuntimeCLIReceipt{
		Format: postRuntimeCLIReceiptFormat, State: executionReceipt.State,
		Manifest: manifestReceipt, Execution: &executionReceipt,
	})
	if outputErr != nil {
		return outputErr
	}
	return runErr
}

func writePostRuntimeCLIReceipt(output io.Writer, receipt postRuntimeCLIReceipt) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}
