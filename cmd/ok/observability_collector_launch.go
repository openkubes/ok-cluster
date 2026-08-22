package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/openkubes/ok-cluster/internal/runner"
)

type observabilityCollectorLaunchPreparation struct {
	Format          string                                               `json:"format"`
	State           string                                               `json:"state"`
	Package         runner.ObservabilityCollectorRuntimePackageReceipt   `json:"package"`
	Plan            runner.ObservabilityCollectorRuntimeInstallationPlan `json:"plan"`
	MutationAllowed bool                                                 `json:"mutationAllowed"`
}

var prepareObservabilityCollectorLaunch = func(config runner.ObservabilityCollectorRuntimePackageFileConfig) (observabilityCollectorLaunchPreparation, error) {
	packaged, err := runner.LoadObservabilityCollectorRuntimePackage(config)
	if err != nil {
		return observabilityCollectorLaunchPreparation{}, err
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		return observabilityCollectorLaunchPreparation{}, err
	}
	plan, err := runner.PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		return observabilityCollectorLaunchPreparation{}, err
	}
	return observabilityCollectorLaunchPreparation{
		Format: "ok147-observability-collector-launch-preparation/v1", State: "PREPARED",
		Package: receipt, Plan: plan, MutationAllowed: false,
	}, nil
}

var executeObservabilityCollectorLaunch = func(ctx context.Context, packageConfig runner.ObservabilityCollectorRuntimePackageFileConfig, authority runner.KubernetesAuthorityConfig, expectedPackageDigest string) (runner.ObservabilityCollectorRuntimeLaunchReceipt, error) {
	packaged, err := runner.LoadObservabilityCollectorRuntimePackage(packageConfig)
	if err != nil {
		return runner.ObservabilityCollectorRuntimeLaunchReceipt{}, err
	}
	plan, err := runner.PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		return runner.ObservabilityCollectorRuntimeLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = plan.Authority
	launcher, err := runner.OpenKubernetesObservabilityCollectorRuntimeLauncher(runner.ObservabilityCollectorRuntimeLauncherConfig{
		Authority: authority, ExpectedPackageDigest: expectedPackageDigest,
	}, packaged)
	if err != nil {
		return runner.ObservabilityCollectorRuntimeLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type observabilityCollectorLaunchFileFlags struct {
	packagePath, receiptPath, expectedReceiptDigest *string
}

func addObservabilityCollectorLaunchFileFlags(flags *flag.FlagSet) *observabilityCollectorLaunchFileFlags {
	return &observabilityCollectorLaunchFileFlags{
		packagePath:           flags.String("package", "", "private 0600 observability collector runtime package"),
		receiptPath:           flags.String("package-receipt", "", "public verified collector package receipt"),
		expectedReceiptDigest: flags.String("expected-package-receipt-digest", "", "exact public receipt SHA-256 identity"),
	}
}

func (values *observabilityCollectorLaunchFileFlags) config() (runner.ObservabilityCollectorRuntimePackageFileConfig, error) {
	if *values.packagePath == "" || *values.receiptPath == "" || *values.expectedReceiptDigest == "" {
		return runner.ObservabilityCollectorRuntimePackageFileConfig{}, errors.New("collector launch package, receipt and receipt digest are required")
	}
	if !sha256DigestPattern.MatchString(*values.expectedReceiptDigest) {
		return runner.ObservabilityCollectorRuntimePackageFileConfig{}, errors.New("collector launch receipt digest must be a lowercase SHA-256 identity")
	}
	return runner.ObservabilityCollectorRuntimePackageFileConfig{
		PackagePath: *values.packagePath, ReceiptPath: *values.receiptPath, ExpectedReceiptDigest: *values.expectedReceiptDigest,
	}, nil
}

func runClusterStageEvidenceObservabilityCollectorLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability collector launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	files := addObservabilityCollectorLaunchFileFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := files.config()
	if err != nil {
		return err
	}
	preparation, err := prepareObservabilityCollectorLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageEvidenceObservabilityCollectorLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability collector launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	files := addObservabilityCollectorLaunchFileFlags(flags)
	expectedPackageDigest := flags.String("expected-package-digest", "", "exact private package digest emitted by launch prepare")
	endpoint := flags.String("installer-api-endpoint", "", "exact workload Kubernetes HTTPS IP endpoint")
	caDigest := flags.String("installer-ca-digest", "", "expected workload installer CA digest")
	tokenFile := flags.String("installer-token-file", "", "bounded workload installer token file")
	caFile := flags.String("installer-ca-file", "", "bounded workload installer CA file")
	execute := flags.Bool("execute", false, "perform the exact single-use four-create collector launch")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("observability collector mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-package-digest", *expectedPackageDigest}, {"--installer-api-endpoint", *endpoint},
		{"--installer-ca-digest", *caDigest}, {"--installer-token-file", *tokenFile}, {"--installer-ca-file", *caFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedPackageDigest) || !sha256DigestPattern.MatchString(*caDigest) {
		return errors.New("collector launch digests must be lowercase SHA-256 identities")
	}
	config, err := files.config()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeObservabilityCollectorLaunch(bounded, config, runner.KubernetesAuthorityConfig{
		Endpoint: *endpoint, TokenFile: *tokenFile, CAFile: *caFile, CABundleDigest: *caDigest,
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
