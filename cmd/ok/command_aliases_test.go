package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestProductCommandAliasesOnlyRewritePrefixes(t *testing.T) {
	for _, test := range []struct{ input, want []string }{
		{[]string{"up"}, []string{"cluster", "create"}},
		{[]string{"up", "-f", "up", "--prepare"}, []string{"cluster", "create", "-f", "up", "--prepare"}},
		{[]string{"help", "up"}, []string{"help", "cluster", "create"}},
		{[]string{"destroy", "cluster", "help", "--config", "up"}, []string{"cluster", "destroy", "help", "--config", "up"}},
		{[]string{"help", "destroy", "cluster"}, []string{"help", "cluster", "destroy"}},
		{[]string{"cluster", "destroy", "up"}, []string{"cluster", "destroy", "up"}},
		{[]string{"create", "cluster"}, []string{"create", "cluster"}},
		{[]string{}, []string{}},
	} {
		before := append([]string{}, test.input...)
		if got := canonicalProductArguments(test.input); !reflect.DeepEqual(got, test.want) {
			t.Fatalf("input=%v got=%v want=%v", test.input, got, test.want)
		}
		if !reflect.DeepEqual(test.input, before) {
			t.Fatal("alias mutated caller's arguments")
		}
	}
}

func TestProductCommandAliasesHelpAndReadOnlySubcommands(t *testing.T) {
	for _, args := range [][]string{{"up"}, {"up", "--help"}, {"help", "up"},
		{"up", "--file", "/must-not-be-read.json", "--help"},
		{"cluster", "destroy"}, {"cluster", "destroy", "--help"}, {"help", "cluster", "destroy"},
		{"destroy", "cluster", "--help"}, {"help", "destroy", "cluster"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil || stdout.Len() == 0 || stderr.Len() != 0 {
			t.Fatalf("args=%v err=%v stderr=%s", args, err, &stderr)
		}
	}
	for _, subcommand := range []string{"requirements", "manifest-template", "plan-template"} {
		var alias, canonical bytes.Buffer
		if err := run([]string{"up", subcommand}, &alias, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"cluster", "create", subcommand}, &canonical, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(alias.Bytes(), canonical.Bytes()) {
			t.Fatalf("%s: alias changed non-authorizing output", subcommand)
		}
	}
}

func TestUpRejectsIncompleteAndAmbiguousExecutionWithoutOpeningManifest(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		t.Fatal("incomplete input opened a manifest")
		return runner.FullRunExecutionManifestReceipt{}, nil
	}
	for _, suffix := range [][]string{
		{"--dry-run"}, {"--file", "/not-read.json"}, {"--file", "a", "-f", "b", "--prepare"},
		{"--file", "a", "--live"}, {"--file", "a", "--execute"}, {"--file", "a", "--dry-run", "--prepare"},
		{"--file", "a", "--prepare", "--contract", "b"}, {"--file", "a", "--dry-run", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(append([]string{"up"}, suffix...), &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatalf("unsafe input accepted: %v err=%v", suffix, err)
		}
	}
}

func TestUpPropagatesRunnerFailureWithoutRetryOrSyntheticSuccess(t *testing.T) {
	previousPrepare, previousExecute, previousMarker := prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest, executeClusterCreateLive, validateClusterCreateTerminalMarker = previousPrepare, previousExecute, previousMarker
	}()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return bareClusterCreateManifestReceipt(), nil
	}
	validateClusterCreateTerminalMarker = func(string) error { return nil }
	calls := 0
	failure := errors.New("runner incomplete; convergence evidence missing")
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error { calls++; return failure }
	var stdout bytes.Buffer
	err := run([]string{"up", "--file", "/fake.json", "--live", "--execute", "--expected-manifest-digest", testSHA("1"),
		"--independent-evidence-public-key", "/fake.pub", "--terminal-marker", "/private/executor-terminal"}, &stdout, &bytes.Buffer{})
	if !errors.Is(err, failure) || calls != 1 || stdout.Len() != 0 {
		t.Fatalf("err=%v calls=%d stdout=%s", err, calls, &stdout)
	}
}

func TestClusterDestroyCanonicalRouteKeepsTerminalGate(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = previous; reader.Close(); writer.Close() }()
	_, args := destroyFixture(t)
	for _, prefix := range [][]string{{"cluster", "destroy"}, {"destroy", "cluster"}} {
		var stdout bytes.Buffer
		err := run(append(append([]string{}, prefix...), args...), &stdout, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "interactive terminal") || stdout.Len() != 0 {
			t.Fatalf("args=%v err=%v", prefix, err)
		}
	}
}
