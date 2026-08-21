package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestRunClusterStageRunFullBindV3EmitsOnlyVerifiedReceipt(t *testing.T) {
	original := bindFreshRunV3
	t.Cleanup(func() { bindFreshRunV3 = original })
	var captured runner.FreshRunV3BindingConfig
	bindFreshRunV3 = func(config runner.FreshRunV3BindingConfig) (runner.FreshRunV3BindingReceipt, error) {
		captured = config
		return runner.FreshRunV3BindingReceipt{Format: runner.FreshRunV3BindingFormat, State: "VERIFIED_NOT_AUTHORIZED"}, nil
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	err := runClusterStageRunFullBindV3([]string{
		"--publication-receipt", "/private/publication.json", "--publication-receipt-digest", "sha256:" + repeatHex("1"),
		"--source-sha", repeatHex40("2"), "--full-run-package-receipt", "/private/full-run.json",
		"--full-run-package-receipt-digest", "sha256:" + repeatHex("3"),
		"--collector-package-receipt", "/private/collector.json", "--collector-package-receipt-digest", "sha256:" + repeatHex("4"),
	}, stdout, stderr)
	if err != nil {
		t.Fatal(err)
	}
	if captured.ExpectedSourceSHA != repeatHex40("2") || captured.CollectorPackageReceiptPath != "/private/collector.json" {
		t.Fatalf("fresh-run v3 CLI lost an input: %#v", captured)
	}
	var receipt runner.FreshRunV3BindingReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED_NOT_AUTHORIZED" {
		t.Fatalf("unexpected CLI receipt: %s", stdout.String())
	}
}

func TestRunClusterStageRunFullBindV3RequiresAllInputs(t *testing.T) {
	if err := runClusterStageRunFullBindV3(nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("incomplete fresh-run v3 binding was accepted")
	}
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}

func repeatHex40(value string) string {
	result := ""
	for len(result) < 40 {
		result += value
	}
	return result[:40]
}
