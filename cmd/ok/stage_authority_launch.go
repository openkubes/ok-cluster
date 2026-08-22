package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/openkubes/ok-cluster/internal/stageauthority"
)

type stageAuthorityLaunchPreparation struct {
	Format          string                                 `json:"format"`
	State           string                                 `json:"state"`
	Package         stageauthority.RuntimePackageReceipt   `json:"package"`
	Plan            stageauthority.RuntimeInstallationPlan `json:"plan"`
	MutationAllowed bool                                   `json:"mutationAllowed"`
}

type stageAuthorityPackageFileFlags struct {
	packagePath, receiptPath, expectedReceiptDigest *string
}

func addStageAuthorityPackageFileFlags(flags *flag.FlagSet) *stageAuthorityPackageFileFlags {
	return &stageAuthorityPackageFileFlags{
		packagePath:           flags.String("package", "", "private 0600 bounded stage-authority runtime package"),
		receiptPath:           flags.String("package-receipt", "", "public verified bounded stage-authority package receipt"),
		expectedReceiptDigest: flags.String("expected-package-receipt-digest", "", "exact public receipt SHA-256 identity"),
	}
}

func (values *stageAuthorityPackageFileFlags) config() (stageauthority.RuntimePackageFileConfig, error) {
	if *values.packagePath == "" || *values.receiptPath == "" || !sha256DigestPattern.MatchString(*values.expectedReceiptDigest) {
		return stageauthority.RuntimePackageFileConfig{}, errors.New("authority launch package, receipt and exact receipt digest are required")
	}
	return stageauthority.RuntimePackageFileConfig{
		PackagePath: *values.packagePath, ReceiptPath: *values.receiptPath, ExpectedReceiptDigest: *values.expectedReceiptDigest,
	}, nil
}

var prepareStageAuthorityRuntimeLaunch = func(config stageauthority.RuntimePackageFileConfig, authority string) (stageAuthorityLaunchPreparation, error) {
	packaged, err := stageauthority.LoadRuntimePackage(config)
	if err != nil {
		return stageAuthorityLaunchPreparation{}, err
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		return stageAuthorityLaunchPreparation{}, err
	}
	plan, err := stageauthority.PlanRuntimeInstallation(packaged, authority)
	if err != nil {
		return stageAuthorityLaunchPreparation{}, err
	}
	return stageAuthorityLaunchPreparation{
		Format: "ok147-bounded-stage-authority-launch-preparation/v1", State: "PREPARED",
		Package: receipt, Plan: plan, MutationAllowed: false,
	}, nil
}

var executeStageAuthorityRuntimeLaunch = func(ctx context.Context, packageConfig stageauthority.RuntimePackageFileConfig, launcherConfig stageauthority.RuntimeLauncherConfig) (stageauthority.RuntimeLaunchReceipt, error) {
	packaged, err := stageauthority.LoadRuntimePackage(packageConfig)
	if err != nil {
		return stageauthority.RuntimeLaunchReceipt{}, err
	}
	launcher, err := stageauthority.OpenKubernetesRuntimeLauncher(launcherConfig, packaged)
	if err != nil {
		return stageauthority.RuntimeLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

func runAuthorityStageLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	files := addStageAuthorityPackageFileFlags(flags)
	authority := flags.String("installer-authority", "", "exact target authority identity; currently ok-mgmt")
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
	preparation, err := prepareStageAuthorityRuntimeLaunch(config, *authority)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runAuthorityStageLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	files := addStageAuthorityPackageFileFlags(flags)
	authority := flags.String("installer-authority", "", "exact target authority identity; currently ok-mgmt")
	endpoint := flags.String("installer-api-endpoint", "", "exact ok-mgmt Kubernetes HTTPS IP endpoint")
	tokenFile := flags.String("installer-token-file", "", "private bounded installer token file")
	caFile := flags.String("installer-ca-file", "", "bounded installer CA file")
	caDigest := flags.String("installer-ca-digest", "", "exact installer CA SHA-256 identity")
	expectedPackageDigest := flags.String("expected-package-digest", "", "exact private package digest from launch prepare")
	execute := flags.Bool("execute", false, "perform the exact single-use six-create launch")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("bounded stage authority mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--installer-authority", *authority}, {"--installer-api-endpoint", *endpoint},
		{"--installer-token-file", *tokenFile}, {"--installer-ca-file", *caFile},
		{"--installer-ca-digest", *caDigest}, {"--expected-package-digest", *expectedPackageDigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*caDigest) || !sha256DigestPattern.MatchString(*expectedPackageDigest) {
		return errors.New("authority launch digests must be lowercase SHA-256 identities")
	}
	packageConfig, err := files.config()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeStageAuthorityRuntimeLaunch(bounded, packageConfig, stageauthority.RuntimeLauncherConfig{
		Endpoint: *endpoint, Authority: *authority, TokenFile: *tokenFile, CAFile: *caFile,
		CABundleDigest: *caDigest, ExpectedPackageDigest: *expectedPackageDigest,
	})
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
