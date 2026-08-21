package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestObservabilityEvidenceProduceRunsOneBoundedIndependentCollection(t *testing.T) {
	previous := produceIndependentObservabilityEvidence
	defer func() { produceIndependentObservabilityEvidence = previous }()
	calls := 0
	produceIndependentObservabilityEvidence = func(ctx context.Context, config observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > config.IdentityWaitTimeout+config.Timeout+observabilityEvidenceProductionOverhead {
			t.Fatalf("evidence production was not bounded: deadline=%v config=%#v", deadline, config)
		}
		if config.OutputPath != "/private/evidence.json" || config.PrivateKeyPath != "/private/evidence.key" ||
			config.IdentityPath != "/private/evidence-identity.json" || config.IdentityReceiptPath != "/private/evidence-identity-receipt.json" ||
			config.ExpectedManifestDigest != testSHA("2") || config.IdentityPollInterval != time.Second || config.IdentityWaitTimeout != 30*time.Minute ||
			config.CollectorEndpoint != "https://192.0.2.50:8443" || config.CollectorToken != "/private/collector-token" ||
			config.CollectorCA != "/private/collector-ca" || config.CollectorCADigest != testSHA("3") ||
			config.ValidFor != 10*time.Minute || config.Timeout != 2*time.Minute {
			t.Fatalf("independent evidence production binding differs: %#v", config)
		}
		return runner.ObservabilityIndependentEvidenceReceipt{
			Format: runner.ObservabilityIndependentEvidenceReceiptFormat, State: "WRITTEN_VERIFIED",
			EvidenceDigest: testSHA("4"), KeyID: testSHA("5"), ObservedAt: "2026-08-21T12:00:00Z",
			ExpiresAt: "2026-08-21T12:10:00Z", FileMode: "0600", FileSize: 512,
		}, nil
	}
	var stdout bytes.Buffer
	if err := run(observabilityEvidenceProduceArguments(), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt runner.ObservabilityIndependentEvidenceReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "WRITTEN_VERIFIED" || calls != 1 {
		t.Fatalf("unexpected evidence production receipt: %#v calls=%d err=%v", receipt, calls, err)
	}
	for _, forbidden := range []string{"/private/", "192.0.2.50", "collector-token", "cluster-uid-ok147"} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatalf("evidence production disclosed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestObservabilityEvidenceProduceFailsClosedBeforeCollector(t *testing.T) {
	previous := produceIndependentObservabilityEvidence
	defer func() { produceIndependentObservabilityEvidence = previous }()
	calls := 0
	produceIndependentObservabilityEvidence = func(context.Context, observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
		calls++
		return runner.ObservabilityIndependentEvidenceReceipt{}, errors.New("unexpected collector call")
	}
	valid := observabilityEvidenceProduceArguments()
	for name, arguments := range map[string][]string{
		"missing produce":     removeArgument(valid, "--produce"),
		"bad manifest digest": replaceArgument(valid, "--expected-manifest-digest", "sha256:bad"),
		"short identity wait": replaceArgument(valid, "--identity-wait-timeout", "500ms"),
		"slow identity poll":  replaceArgument(valid, "--identity-poll-interval", "31s"),
		"bad CA digest":       replaceArgument(valid, "--collector-ca-digest", "sha256:bad"),
		"short validity":      replaceArgument(valid, "--valid-for", "30s"),
		"long collection":     replaceArgument(valid, "--timeout", "31m"),
		"positional":          append(append([]string(nil), valid...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe evidence production input was accepted")
			}
			if calls != 0 {
				t.Fatalf("unsafe input reached evidence collector: calls=%d", calls)
			}
		})
	}
}

func TestObservabilityEvidenceProducePreservesStoppedReceipt(t *testing.T) {
	previous := produceIndependentObservabilityEvidence
	defer func() { produceIndependentObservabilityEvidence = previous }()
	produceIndependentObservabilityEvidence = func(context.Context, observabilityEvidenceProductionConfig) (runner.ObservabilityIndependentEvidenceReceipt, error) {
		return runner.ObservabilityIndependentEvidenceReceipt{
			Format: runner.ObservabilityIndependentEvidenceReceiptFormat, State: "STOPPED_ZERO_WRITE",
		}, errors.New("independent authority unavailable")
	}
	var stdout bytes.Buffer
	err := run(observabilityEvidenceProduceArguments(), &stdout, &bytes.Buffer{})
	var receipt runner.ObservabilityIndependentEvidenceReceipt
	if err == nil || json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.State != "STOPPED_ZERO_WRITE" {
		t.Fatalf("stopped evidence receipt was not preserved: receipt=%#v err=%v", receipt, err)
	}
}

func observabilityEvidenceProduceArguments() []string {
	return []string{
		"cluster", "stage", "evidence", "observability", "produce",
		"--output", "/private/evidence.json", "--private-key", "/private/evidence.key",
		"--identity-file", "/private/evidence-identity.json", "--identity-receipt-file", "/private/evidence-identity-receipt.json",
		"--expected-manifest-digest", testSHA("2"), "--identity-poll-interval", "1s", "--identity-wait-timeout", "30m",
		"--collector-endpoint", "https://192.0.2.50:8443", "--collector-token-file", "/private/collector-token",
		"--collector-ca-file", "/private/collector-ca", "--collector-ca-digest", testSHA("3"),
		"--valid-for", "10m", "--timeout", "2m", "--produce",
	}
}

func TestObservabilityEvidenceIdentityMaterializeWritesOnlyRedactedReceipt(t *testing.T) {
	previous := materializeObservabilityEvidenceIdentity
	defer func() { materializeObservabilityEvidenceIdentity = previous }()
	calls := 0
	materializeObservabilityEvidenceIdentity = func(config runner.ObservabilityIndependentEvidenceIdentityMaterialConfig) (runner.ObservabilityIndependentEvidenceIdentityReceipt, error) {
		calls++
		if config.ManifestPath != "/private/full-run.json" || config.ExpectedManifestDigest != testSHA("1") ||
			config.ReceiptPrefixPath != "/private/six-prefix.json" || config.ExpectedReceiptPrefixDigest != testSHA("2") ||
			config.OutputPath != "/private/evidence-identity.json" {
			t.Fatalf("identity materialization differs: %#v", config)
		}
		return runner.ObservabilityIndependentEvidenceIdentityReceipt{
			Format: runner.ObservabilityIndependentEvidenceIdentityReceiptFormat, State: "WRITTEN_VERIFIED",
			ManifestDigest: testSHA("1"), RuntimeBindingDigest: testSHA("3"), TargetClusterUIDDigest: testSHA("4"),
			IdentityDigest: testSHA("5"), FileMode: "0600", FileSize: 512,
		}, nil
	}
	arguments := []string{
		"cluster", "stage", "evidence", "observability", "identity", "materialize",
		"--manifest", "/private/full-run.json", "--expected-manifest-digest", testSHA("1"),
		"--receipt-prefix", "/private/six-prefix.json", "--expected-receipt-prefix-digest", testSHA("2"),
		"--output", "/private/evidence-identity.json", "--materialize",
	}
	var stdout bytes.Buffer
	if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || strings.Contains(stdout.String(), "/private/") || strings.Contains(stdout.String(), "cluster-uid") {
		t.Fatalf("unsafe identity materialization output: calls=%d output=%s", calls, stdout.String())
	}
	for name, invalid := range map[string][]string{
		"missing activation": removeArgument(arguments, "--materialize"),
		"bad manifest":       replaceArgument(arguments, "--expected-manifest-digest", "bad"),
		"bad prefix":         replaceArgument(arguments, "--expected-receipt-prefix-digest", "bad"),
		"positional":         append(append([]string(nil), arguments...), "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(invalid, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || calls != before {
				t.Fatalf("unsafe materialization input reached writer: calls=%d before=%d err=%v", calls, before, err)
			}
		})
	}
}
