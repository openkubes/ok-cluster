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

const fullRunExecutionTimeout = 3 * time.Hour

type fullRunActivationRunner interface {
	Run(context.Context) (runner.FullRunExecutionActivationReceipt, error)
}

type fullRunActivationLaunchPreparation struct {
	Format          string                                            `json:"format"`
	State           string                                            `json:"state"`
	Package         runner.FullRunExecutionActivationPackageReceipt   `json:"package"`
	Plan            runner.FullRunExecutionActivationInstallationPlan `json:"plan"`
	MutationAllowed bool                                              `json:"mutationAllowed"`
}

var prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
	_, receipt, err := runner.LoadFullRunExecutionManifest(path)
	return receipt, err
}

var materializeFullRunExecutionBundle = runner.MaterializeFullRunExecutionBundle

var materializeFullRunExecutionActivationPackage = func(config runner.FullRunExecutionActivationPackageConfig) ([]byte, runner.FullRunExecutionActivationPackageReceipt, error) {
	packaged, err := runner.BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		return nil, runner.FullRunExecutionActivationPackageReceipt{}, err
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		return nil, runner.FullRunExecutionActivationPackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var prepareFullRunExecutionActivationLaunch = func(config runner.FullRunExecutionActivationPackageConfig) (fullRunActivationLaunchPreparation, error) {
	packaged, err := runner.BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		return fullRunActivationLaunchPreparation{}, err
	}
	packageReceipt, err := packaged.Receipt()
	if err != nil {
		return fullRunActivationLaunchPreparation{}, err
	}
	plan, err := runner.PlanFullRunExecutionActivationInstallation(packaged)
	if err != nil {
		return fullRunActivationLaunchPreparation{}, err
	}
	return fullRunActivationLaunchPreparation{
		Format: "ok147-full-run-activation-launch-preparation/v1", State: "PREPARED",
		Package: packageReceipt, Plan: plan, MutationAllowed: false,
	}, nil
}

var executeFullRunExecutionActivationLaunch = func(ctx context.Context, config runner.FullRunExecutionActivationPackageConfig, authority runner.KubernetesAuthorityConfig, expectedPackageDigest string) (runner.FullRunExecutionActivationLaunchReceipt, error) {
	packaged, err := runner.BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		return runner.FullRunExecutionActivationLaunchReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		return runner.FullRunExecutionActivationLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = receipt.ManagementAuthority
	launcher, err := runner.OpenKubernetesFullRunExecutionActivationLauncher(runner.FullRunExecutionActivationLauncherConfig{
		Authority: authority, ExpectedPackageDigest: expectedPackageDigest,
	}, packaged)
	if err != nil {
		return runner.FullRunExecutionActivationLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

var openKubernetesObservabilityFullRunActivation = func(path, publicKeyPath string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
	return runner.OpenKubernetesObservabilityFullRunActivation(path, runner.KubernetesObservabilityFullRunActivationConfig{
		IndependentEvidencePublicKeyPath: publicKeyPath, Clock: time.Now, Wait: runner.WaitWithTimer,
	})
}

type fullRunActivationPackageFlags struct {
	manifest, evidencePublicKey, activationSecret                 *string
	evidenceAuthoritySecret, evidencePrivateKey                   *string
	collectorEndpoint, collectorToken, collectorCA, collectorCAID *string
	jobTemplate, jobTemplateDigest, runID, imageDigest            *string
	infrastructureCIDR, managementCIDR, workloadURL, workloadCIDR *string
	argoCIDR, authorizationCIDR, collectorCIDR                    *string
	identityPollInterval, identityWaitTimeout                     *time.Duration
	evidenceValidFor, collectionTimeout                           *time.Duration
}

func addFullRunActivationPackageFlags(flags *flag.FlagSet) *fullRunActivationPackageFlags {
	values := &fullRunActivationPackageFlags{}
	values.manifest = flags.String("manifest", "", "path to the verified private full-run manifest")
	values.evidencePublicKey = flags.String("independent-evidence-public-key", "", "pinned independent evidence public key")
	values.activationSecret = flags.String("activation-secret", "", "immutable private executor activation Secret name")
	values.evidenceAuthoritySecret = flags.String("evidence-authority-secret", "", "immutable private evidence-authority Secret name")
	values.evidencePrivateKey = flags.String("evidence-private-key", "", "private Ed25519 evidence-authority key")
	values.collectorEndpoint = flags.String("collector-endpoint", "", "exact HTTPS independent-evidence collector endpoint")
	values.collectorToken = flags.String("collector-token-file", "", "bounded evidence collector bearer-token file")
	values.collectorCA = flags.String("collector-ca-file", "", "bounded evidence collector CA file")
	values.collectorCAID = flags.String("collector-ca-digest", "", "expected evidence collector CA identity")
	values.identityPollInterval = flags.Duration("identity-poll-interval", 0, "private identity polling interval")
	values.identityWaitTimeout = flags.Duration("identity-wait-timeout", 0, "bounded private identity wait")
	values.evidenceValidFor = flags.Duration("evidence-valid-for", 0, "signed evidence validity")
	values.collectionTimeout = flags.Duration("collection-timeout", 0, "single evidence collection timeout")
	values.jobTemplate = flags.String("job-template", "", "path to the bounded full-run Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 full-run Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.infrastructureCIDR = flags.String("infrastructure-api-cidr", "", "single-address infrastructure API CIDR")
	values.managementCIDR = flags.String("management-api-cidr", "", "single-address management API CIDR")
	values.workloadURL = flags.String("workload-api-url", "", "exact disposable workload API URL")
	values.workloadCIDR = flags.String("workload-api-cidr", "", "single-address workload API CIDR")
	values.argoCIDR = flags.String("argo-api-cidr", "", "single-address Argo API CIDR")
	values.authorizationCIDR = flags.String("authorization-api-cidr", "", "single-address authorization API CIDR")
	values.collectorCIDR = flags.String("collector-api-cidr", "", "single-address evidence collector API CIDR")
	return values
}

func (values *fullRunActivationPackageFlags) config() (runner.FullRunExecutionActivationPackageConfig, error) {
	for _, input := range []struct{ name, value string }{
		{"--manifest", *values.manifest}, {"--independent-evidence-public-key", *values.evidencePublicKey},
		{"--activation-secret", *values.activationSecret}, {"--evidence-authority-secret", *values.evidenceAuthoritySecret},
		{"--evidence-private-key", *values.evidencePrivateKey}, {"--collector-endpoint", *values.collectorEndpoint},
		{"--collector-token-file", *values.collectorToken}, {"--collector-ca-file", *values.collectorCA},
		{"--collector-ca-digest", *values.collectorCAID}, {"--job-template", *values.jobTemplate},
		{"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--infrastructure-api-cidr", *values.infrastructureCIDR}, {"--management-api-cidr", *values.managementCIDR},
		{"--workload-api-url", *values.workloadURL}, {"--workload-api-cidr", *values.workloadCIDR},
		{"--argo-api-cidr", *values.argoCIDR}, {"--authorization-api-cidr", *values.authorizationCIDR},
		{"--collector-api-cidr", *values.collectorCIDR},
	} {
		if input.value == "" {
			return runner.FullRunExecutionActivationPackageConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*values.jobTemplateDigest) || !sha256DigestPattern.MatchString(*values.collectorCAID) {
		return runner.FullRunExecutionActivationPackageConfig{}, errors.New("full-run package digests must be lowercase SHA-256 identities")
	}
	if *values.identityPollInterval < time.Millisecond || *values.identityPollInterval > 30*time.Second ||
		*values.identityWaitTimeout < time.Second || *values.identityWaitTimeout > fullRunExecutionTimeout ||
		*values.evidenceValidFor < time.Minute || *values.evidenceValidFor > 30*time.Minute ||
		*values.collectionTimeout < time.Second || *values.collectionTimeout > 30*time.Minute {
		return runner.FullRunExecutionActivationPackageConfig{}, errors.New("full-run evidence timing bounds are invalid")
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.FullRunExecutionActivationPackageConfig{}, errors.New("read bounded full-run Job template")
	}
	return runner.FullRunExecutionActivationPackageConfig{
		ManifestPath: *values.manifest, IndependentEvidencePublicKey: *values.evidencePublicKey,
		ActivationSecret: *values.activationSecret,
		EvidenceAuthority: runner.ObservabilityEvidenceAuthorityPackageConfig{
			ActivationSecret: *values.evidenceAuthoritySecret, PrivateKeyPath: *values.evidencePrivateKey,
			CollectorEndpoint: *values.collectorEndpoint, CollectorTokenPath: *values.collectorToken,
			CollectorCAPath: *values.collectorCA, CollectorCADigest: *values.collectorCAID,
			RuntimeAuthorityRoot: "/var/run/openkubes/evidence-authority", RuntimeHandoffRoot: "/var/run/openkubes/handoff",
			IdentityPollInterval: *values.identityPollInterval, IdentityWaitTimeout: *values.identityWaitTimeout,
			EvidenceValidFor: *values.evidenceValidFor, CollectionTimeout: *values.collectionTimeout,
		},
		JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest,
		Job: runner.FullRunExecutionJobValues{
			RunID: *values.runID, ImageDigest: *values.imageDigest,
			InfrastructureAPICIDR: *values.infrastructureCIDR, ManagementAPICIDR: *values.managementCIDR,
			WorkloadAPIURL: *values.workloadURL, WorkloadAPICIDR: *values.workloadCIDR,
			ArgoAPICIDR: *values.argoCIDR, AuthorizationAPICIDR: *values.authorizationCIDR,
			CollectorAPICIDR: *values.collectorCIDR,
		},
	}, nil
}

func runClusterStageRunFullPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addFullRunActivationPackageFlags(flags)
	output := flags.String("output", "", "new private 0600 full-run activation package file")
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
	raw, receipt, err := materializeFullRunExecutionActivationPackage(config)
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return errors.New("write private full-run activation package")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStageRunFullLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addFullRunActivationPackageFlags(flags)
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
	preparation, err := prepareFullRunExecutionActivationLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageRunFullLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run full launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	packageFlags := addFullRunActivationPackageFlags(flags)
	expectedPackageDigest := flags.String("expected-package-digest", "", "exact private package digest emitted by launch prepare")
	installerEndpoint := flags.String("installer-api-endpoint", "", "exact management Kubernetes HTTPS IP endpoint")
	installerCADigest := flags.String("installer-ca-digest", "", "expected management installer CA digest")
	installerTokenFile := flags.String("installer-token-file", "", "bounded management installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded management installer CA file")
	execute := flags.Bool("execute", false, "perform the exact single-use four-create full-run activation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("full-run activation mutation requires explicit --execute")
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
		return errors.New("full-run launch digests must be lowercase SHA-256 identities")
	}
	config, err := packageFlags.config()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeFullRunExecutionActivationLaunch(bounded, config, runner.KubernetesAuthorityConfig{
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
	if err != nil {
		return fmt.Errorf("prepare full-run manifest: %w", err)
	}
	if verified.Format != runner.FullRunExecutionManifestReceiptFormat || verified.State != "VERIFIED" || verified.MutationAllowed {
		return errors.New("full-run manifest preparation did not produce a verified identity")
	}
	if verified.ManifestDigest != *expectedManifestDigest {
		return errors.New("full-run manifest differs from the prepared identity")
	}
	activation, prepared, err := openKubernetesObservabilityFullRunActivation(*manifestPath, *evidencePublicKey)
	if err != nil {
		return err
	}
	if activation == nil || prepared.Format != runner.FullRunExecutionActivationReceiptFormat || prepared.State != "PREPARED" ||
		prepared.Execution != nil || prepared.Manifest.State != "VERIFIED" || prepared.Manifest.MutationAllowed {
		return errors.New("full-run activation did not produce a prepared identity")
	}
	if prepared.Manifest != verified {
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
