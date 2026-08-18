package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

var preparePostRuntimeActivationLaunch = func(config runner.PostRuntimeExecutionActivationPackageConfig) (postRuntimeActivationLaunchPreparation, error) {
	packaged, err := runner.BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		return postRuntimeActivationLaunchPreparation{}, err
	}
	packageReceipt, err := packaged.Receipt()
	if err != nil {
		return postRuntimeActivationLaunchPreparation{}, err
	}
	plan, err := runner.PlanPostRuntimeExecutionActivationInstallation(packaged)
	if err != nil {
		return postRuntimeActivationLaunchPreparation{}, err
	}
	return postRuntimeActivationLaunchPreparation{
		Format: "ok147-post-runtime-activation-launch-preparation/v1", State: "PREPARED",
		Package: packageReceipt, Plan: plan, MutationAllowed: false,
	}, nil
}

var executePostRuntimeActivationLaunch = func(ctx context.Context, config runner.PostRuntimeExecutionActivationPackageConfig, authority runner.KubernetesAuthorityConfig, expectedPackageDigest string) (runner.PostRuntimeExecutionActivationLaunchReceipt, error) {
	packaged, err := runner.BuildPostRuntimeExecutionActivationPackage(config)
	if err != nil {
		return runner.PostRuntimeExecutionActivationLaunchReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		return runner.PostRuntimeExecutionActivationLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = receipt.ManagementAuthority
	launcher, err := runner.OpenKubernetesPostRuntimeExecutionActivationLauncher(runner.PostRuntimeExecutionActivationLauncherConfig{
		Authority: authority, ExpectedPackageDigest: expectedPackageDigest,
	}, packaged)
	if err != nil {
		return runner.PostRuntimeExecutionActivationLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

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

type postRuntimeActivationLaunchPreparation struct {
	Format          string                                                `json:"format"`
	State           string                                                `json:"state"`
	Package         runner.PostRuntimeExecutionActivationPackageReceipt   `json:"package"`
	Plan            runner.PostRuntimeExecutionActivationInstallationPlan `json:"plan"`
	MutationAllowed bool                                                  `json:"mutationAllowed"`
}

type postRuntimeActivationPackageFlags struct {
	manifest, activationSecret, jobTemplate, jobTemplateDigest *string
	runID, imageDigest                                         *string
	managementCIDR, workloadCIDR, argoCIDR, authorizationCIDR  *string
}

func addPostRuntimeActivationPackageFlags(flags *flag.FlagSet) *postRuntimeActivationPackageFlags {
	values := &postRuntimeActivationPackageFlags{}
	values.manifest = flags.String("manifest", "", "path to the verified local post-runtime manifest")
	values.activationSecret = flags.String("activation-secret", "", "immutable private activation Secret name")
	values.jobTemplate = flags.String("job-template", "", "path to the bounded post-runtime Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 post-runtime Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.managementCIDR = flags.String("management-api-cidr", "", "single-address management API CIDR")
	values.workloadCIDR = flags.String("workload-api-cidr", "", "single-address workload API CIDR")
	values.argoCIDR = flags.String("argo-api-cidr", "", "single-address Argo API CIDR")
	values.authorizationCIDR = flags.String("authorization-api-cidr", "", "single-address authorization API CIDR")
	return values
}

func (values *postRuntimeActivationPackageFlags) config() (runner.PostRuntimeExecutionActivationPackageConfig, error) {
	for _, input := range []struct{ name, value string }{
		{"--manifest", *values.manifest}, {"--activation-secret", *values.activationSecret},
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest},
		{"--run-id", *values.runID}, {"--image", *values.imageDigest}, {"--management-api-cidr", *values.managementCIDR},
		{"--workload-api-cidr", *values.workloadCIDR}, {"--argo-api-cidr", *values.argoCIDR},
		{"--authorization-api-cidr", *values.authorizationCIDR},
	} {
		if input.value == "" {
			return runner.PostRuntimeExecutionActivationPackageConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*values.jobTemplateDigest) {
		return runner.PostRuntimeExecutionActivationPackageConfig{}, errors.New("--job-template-digest must be a lowercase SHA-256 identity")
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.PostRuntimeExecutionActivationPackageConfig{}, errors.New("read bounded post-runtime Job template")
	}
	return runner.PostRuntimeExecutionActivationPackageConfig{
		ManifestPath: *values.manifest, ActivationSecret: *values.activationSecret, JobTemplate: template,
		JobTemplateDigest: *values.jobTemplateDigest, RunID: *values.runID, ImageDigest: *values.imageDigest,
		ManagementAPICIDR: *values.managementCIDR, WorkloadAPICIDR: *values.workloadCIDR,
		ArgoAPICIDR: *values.argoCIDR, AuthorizationAPICIDR: *values.authorizationCIDR,
	}, nil
}

func runClusterStageRunPostRuntimePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addPostRuntimeActivationPackageFlags(flags)
	output := flags.String("output", "", "new private 0600 activation package file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *output == "" {
		return errors.New("--output is required")
	}
	config, err := packageFlags.config()
	if err != nil {
		return err
	}
	raw, receipt, err := materializePostRuntimeActivationPackage(config)
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

func runClusterStageRunPostRuntimeLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addPostRuntimeActivationPackageFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := packageFlags.config()
	if err != nil {
		return err
	}
	preparation, err := preparePostRuntimeActivationLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageRunPostRuntimeLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run post-runtime launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addPostRuntimeActivationPackageFlags(flags)
	expectedPackageDigest := flags.String("expected-package-digest", "", "exact private package digest emitted by launch prepare")
	installerEndpoint := flags.String("installer-api-endpoint", "", "exact management Kubernetes HTTPS IP endpoint")
	installerCADigest := flags.String("installer-ca-digest", "", "expected management installer CA digest")
	installerTokenFile := flags.String("installer-token-file", "", "bounded management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	execute := flags.Bool("execute", false, "perform the exact single-use three-create post-runtime activation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("post-runtime activation mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-package-digest", *expectedPackageDigest}, {"--installer-api-endpoint", *installerEndpoint},
		{"--installer-ca-digest", *installerCADigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedPackageDigest) || !sha256DigestPattern.MatchString(*installerCADigest) {
		return errors.New("post-runtime launch digests must be lowercase SHA-256 identities")
	}
	config, err := packageFlags.config()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executePostRuntimeActivationLaunch(bounded, config, runner.KubernetesAuthorityConfig{
		Endpoint: *installerEndpoint, TokenFile: *installerTokenFile, CAFile: *installerCAFile, CABundleDigest: *installerCADigest,
	}, *expectedPackageDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
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
