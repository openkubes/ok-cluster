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

var materializePostRuntimeBundle = runner.MaterializePostRuntimeExecutionBundle

var materializePostRuntimeActivationPackage = func(config runner.PostRuntimeExecutionActivationPackageConfig) ([]byte, runner.PostRuntimeExecutionActivationPackageReceipt, error) {
	packaged, err := runner.BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		return nil, runner.PostRuntimeExecutionActivationPackageReceipt{}, err
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		return nil, runner.PostRuntimeExecutionActivationPackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

type postRuntimeCLIReceipt struct {
	Format    string                                     `json:"format"`
	State     string                                     `json:"state"`
	Manifest  runner.PostRuntimeExecutionManifestReceipt `json:"manifest"`
	Execution *runner.PostRuntimeExecutionReceipt        `json:"execution,omitempty"`
}

func runClusterStageRunPostRuntimePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifest := flags.String("manifest", "", "path to the verified local post-runtime manifest")
	activationSecret := flags.String("activation-secret", "", "immutable private activation Secret name")
	jobTemplate := flags.String("job-template", "", "path to the bounded post-runtime Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new private 0600 activation package file")
	runID := flags.String("run-id", "", "bounded OK-147 post-runtime Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	managementCIDR := flags.String("management-api-cidr", "", "single-address management API CIDR")
	workloadCIDR := flags.String("workload-api-cidr", "", "single-address workload API CIDR")
	argoCIDR := flags.String("argo-api-cidr", "", "single-address Argo API CIDR")
	authorizationCIDR := flags.String("authorization-api-cidr", "", "single-address authorization API CIDR")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, value := range []string{*manifest, *activationSecret, *jobTemplate, *jobTemplateDigest, *output, *runID, *imageDigest, *managementCIDR, *workloadCIDR, *argoCIDR, *authorizationCIDR} {
		if value == "" {
			return errors.New("all post-runtime package flags are required")
		}
	}
	if !sha256DigestPattern.MatchString(*jobTemplateDigest) {
		return errors.New("--job-template-digest must be a lowercase SHA-256 identity")
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return errors.New("read bounded post-runtime Job template")
	}
	raw, receipt, err := materializePostRuntimeActivationPackage(runner.PostRuntimeExecutionActivationPackageConfig{
		ManifestPath: *manifest, ActivationSecret: *activationSecret, JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, ManagementAPICIDR: *managementCIDR, WorkloadAPICIDR: *workloadCIDR,
		ArgoAPICIDR: *argoCIDR, AuthorizationAPICIDR: *authorizationCIDR,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return errors.New("write private post-runtime activation package")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStageRunPostRuntimeMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "projected immutable post-runtime bundle directory")
	destination := flags.String("destination", "", "absent private workspace destination")
	expectedBundleDigest := flags.String("expected-bundle-digest", "", "exact canonical bundle index digest")
	materialize := flags.Bool("materialize", false, "create the private regular-file workspace")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*materialize {
		return errors.New("post-runtime private materialization requires explicit --materialize")
	}
	if *source == "" || *destination == "" || !sha256DigestPattern.MatchString(*expectedBundleDigest) {
		return errors.New("--source, --destination and a lowercase SHA-256 --expected-bundle-digest are required")
	}
	receipt, err := materializePostRuntimeBundle(runner.PostRuntimeExecutionBundleMaterializationConfig{
		SourceDirectory: *source, DestinationDirectory: *destination, ExpectedBundleDigest: *expectedBundleDigest,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if outputErr := encoder.Encode(receipt); outputErr != nil {
		return outputErr
	}
	return err
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
