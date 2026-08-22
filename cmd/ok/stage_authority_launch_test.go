package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/stageauthority"
)

func TestAuthorityStageLaunchPrepareIsOfflineAndNonAuthorizing(t *testing.T) {
	original := prepareStageAuthorityRuntimeLaunch
	defer func() { prepareStageAuthorityRuntimeLaunch = original }()
	called := false
	prepareStageAuthorityRuntimeLaunch = func(config stageauthority.RuntimePackageFileConfig, authority string) (stageAuthorityLaunchPreparation, error) {
		called = config.PackagePath == "/private/package" && config.ReceiptPath == "/public/receipt" && authority == "ok-mgmt"
		return stageAuthorityLaunchPreparation{
			Format: "ok147-bounded-stage-authority-launch-preparation/v1", State: "PREPARED",
			Plan:            stageauthority.RuntimeInstallationPlan{Format: stageauthority.RuntimeInstallationPlanFormat, State: "VERIFIED", Authority: authority, MutationAllowed: false},
			MutationAllowed: false,
		}, nil
	}
	stdout := &bytes.Buffer{}
	err := run([]string{
		"authority", "stage", "launch", "prepare", "--package", "/private/package", "--package-receipt", "/public/receipt",
		"--expected-package-receipt-digest", cliAuthorityDigest("a"), "--installer-authority", "ok-mgmt",
	}, stdout, &bytes.Buffer{})
	if err != nil || !called {
		t.Fatalf("prepare failed: called=%v err=%v", called, err)
	}
	var result stageAuthorityLaunchPreparation
	if json.Unmarshal(stdout.Bytes(), &result) != nil || result.State != "PREPARED" || result.MutationAllowed {
		t.Fatalf("unexpected preparation: %#v", result)
	}
}

func TestAuthorityStageLaunchExecuteRequiresExplicitMutationFlag(t *testing.T) {
	called := false
	original := executeStageAuthorityRuntimeLaunch
	defer func() { executeStageAuthorityRuntimeLaunch = original }()
	executeStageAuthorityRuntimeLaunch = func(context.Context, stageauthority.RuntimePackageFileConfig, stageauthority.RuntimeLauncherConfig) (stageauthority.RuntimeLaunchReceipt, error) {
		called = true
		return stageauthority.RuntimeLaunchReceipt{}, nil
	}
	err := run([]string{
		"authority", "stage", "launch", "execute", "--package", "/private/package", "--package-receipt", "/public/receipt",
		"--expected-package-receipt-digest", cliAuthorityDigest("a"), "--installer-authority", "ok-mgmt",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || called {
		t.Fatalf("launch without --execute reached mutation: called=%v err=%v", called, err)
	}
}

func TestAuthorityStageLaunchExecuteBindsExactInputsAndReceipt(t *testing.T) {
	original := executeStageAuthorityRuntimeLaunch
	defer func() { executeStageAuthorityRuntimeLaunch = original }()
	called := false
	executeStageAuthorityRuntimeLaunch = func(ctx context.Context, files stageauthority.RuntimePackageFileConfig, config stageauthority.RuntimeLauncherConfig) (stageauthority.RuntimeLaunchReceipt, error) {
		_, bounded := ctx.Deadline()
		called = bounded && files.PackagePath == "/private/package" && files.ReceiptPath == "/public/receipt" &&
			config.Authority == "ok-mgmt" && config.Endpoint == "https://192.0.2.10:6443" &&
			config.TokenFile == "/private/token" && config.CAFile == "/private/ca" &&
			config.CABundleDigest == cliAuthorityDigest("b") && config.ExpectedPackageDigest == cliAuthorityDigest("c")
		return stageauthority.RuntimeLaunchReceipt{
			Format: stageauthority.RuntimeLaunchReceiptFormat, Authority: "ok-mgmt", PackageDigest: config.ExpectedPackageDigest,
			State: "INSTALLED", MutationState: "ATTEMPTED", Results: []stageauthority.RuntimeInstalledObject{},
		}, nil
	}
	stdout := &bytes.Buffer{}
	err := run([]string{
		"authority", "stage", "launch", "execute", "--package", "/private/package", "--package-receipt", "/public/receipt",
		"--expected-package-receipt-digest", cliAuthorityDigest("a"), "--installer-authority", "ok-mgmt",
		"--installer-api-endpoint", "https://192.0.2.10:6443", "--installer-token-file", "/private/token",
		"--installer-ca-file", "/private/ca", "--installer-ca-digest", cliAuthorityDigest("b"),
		"--expected-package-digest", cliAuthorityDigest("c"), "--execute",
	}, stdout, &bytes.Buffer{})
	if err != nil || !called {
		t.Fatalf("execute failed: called=%v err=%v", called, err)
	}
	var receipt stageauthority.RuntimeLaunchReceipt
	if json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.State != "INSTALLED" || receipt.PackageDigest != cliAuthorityDigest("c") {
		t.Fatalf("unexpected execute receipt: %#v", receipt)
	}
}
