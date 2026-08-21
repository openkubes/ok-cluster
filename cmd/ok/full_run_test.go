package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestFullRunPrepareVerifiesWithoutExecutionSurface(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	calls := 0
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		calls++
		if path != "/private/full-run.json" {
			t.Fatalf("full-run manifest path differs: %q", path)
		}
		return fullRunCLITestManifestReceipt("VERIFIED"), nil
	}
	var stdout bytes.Buffer
	if err := run([]string{"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionActivationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || calls != 1 || receipt.Format != runner.FullRunExecutionActivationReceiptFormat || receipt.State != "PREPARED" || receipt.Manifest.ManifestDigest != testSHA("1") || receipt.Execution != nil {
		t.Fatalf("unexpected full-run preparation: receipt=%#v calls=%d err=%v", receipt, calls, err)
	}
	for _, forbidden := range []string{"/private/", "token", "endpoint", "kubeconfig", "certificate", "targetidentity"} {
		if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
			t.Fatalf("full-run preparation disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestFullRunPrepareFailsClosed(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	calls := 0
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		calls++
		return runner.FullRunExecutionManifestReceipt{}, errors.New("private manifest rejected")
	}
	for name, arguments := range map[string][]string{
		"missing manifest": {"cluster", "stage", "run", "full", "prepare"},
		"positional":       {"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json", "extra"},
		"load rejection":   {"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"},
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatal("unsafe full-run preparation was accepted")
			}
			if name != "load rejection" && calls != before {
				t.Fatalf("invalid CLI input reached manifest loader: calls=%d before=%d", calls, before)
			}
		})
	}

	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return fullRunCLITestManifestReceipt("STOPPED"), nil
	}
	if err := run([]string{"cluster", "stage", "run", "full", "prepare", "--manifest", "/private/full-run.json"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unverified full-run receipt was accepted")
	}
	if err := run([]string{"cluster", "stage", "run", "full", "execute", "--manifest", "/private/full-run.json", "--execute"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unimplemented full-run execute surface was accepted")
	}
}

func fullRunCLITestManifestReceipt(state string) runner.FullRunExecutionManifestReceipt {
	return runner.FullRunExecutionManifestReceipt{
		Format: runner.FullRunExecutionManifestReceiptFormat, State: state,
		ManifestDigest: testSHA("1"), PlanDigest: testSHA("2"),
		ProjectionManifestDigest: testSHA("3"), ProjectionAuthorityDigest: testSHA("4"),
		NetworkProfileDigest: testSHA("5"), PlatformProfileDigest: testSHA("6"), AggregateProfileDigest: testSHA("7"),
		RuntimeIdentityMode: "lifecycle-derived-private/v1", AuthorizationMode: "predecessor-bound-tls/v1",
		CapabilityMode: "runtime-bound-in-memory/v1", MutationAllowed: false,
	}
}
