package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func destroyFixture(t *testing.T) (string, []string) {
	t.Helper()
	isolatedConfigHome(t)
	root := filepath.Join(t.TempDir(), "trusted checkout with spaces")
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"scripts/talos_golden_lifecycle.py", "management.yaml", "provider.yaml"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("# fixture only\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, []string{"demo-cluster", "--lifecycle-root", root,
		"--management-kubeconfig", filepath.Join(root, "management.yaml"),
		"--provider-kubeconfig", filepath.Join(root, "provider.yaml")}
}

func TestDestroyHierarchicalHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"destroy"}, {"destroy", "--help"},
		{"help", "destroy"}, {"destroy", "cluster"}, {"destroy", "cluster", "--help"},
		{"help", "destroy", "cluster"}, {"destroy", "cluster", "demo-cluster", "--help"}} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(stdout.String(), "destroy") || stderr.Len() != 0 {
			t.Fatalf("unexpected help: %s %s", &stdout, &stderr)
		}
	}
}

func TestDestroyOnlyExactOKLaunchesLifecycleOnce(t *testing.T) {
	root, args := destroyFixture(t)
	var stdout, stderr bytes.Buffer
	calls := 0
	err := runDestroyClusterWithRuntime(context.Background(), args, &stdout, &stderr, destroyClusterRuntime{
		input: strings.NewReader("ok\n"), interactive: true,
		execute: func(ctx context.Context, dir string, argv []string, out, errOut io.Writer) error {
			calls++
			expected := []string{filepath.Join(root, "scripts", "talos_golden_lifecycle.py"),
				"--teardown", "--cluster", "demo-cluster", "--cluster-dir", filepath.Join(root, "demo-cluster"),
				"--kubeconfig", filepath.Join(root, "management.yaml"),
				"--provider-kubeconfig", filepath.Join(root, "provider.yaml"),
				"--ok-linux-path", filepath.Join(filepath.Dir(root), "ok-linux"),
				"--preserve-local", "--confirm", "yes"}
			if dir != root || !reflect.DeepEqual(argv, expected) {
				t.Fatalf("unexpected delegation: %s %v", dir, argv)
			}
			if !strings.Contains(stdout.String(), "Type ok to delete") ||
				!strings.Contains(stdout.String(), "demo-cluster") {
				t.Fatal("invoked before displaying target and confirmation")
			}
			fmt.Fprintln(out, "owner outcome evidence")
			return nil
		},
	})
	if err != nil || calls != 1 || !strings.Contains(stdout.String(), "owner outcome evidence") {
		t.Fatalf("err=%v calls=%d stdout=%s", err, calls, &stdout)
	}
	if strings.Contains(stdout.String(), "success") {
		t.Fatal("CLI synthesized success from command execution")
	}
}

func TestDestroyCancelAndInvalidAnswersNeverInvoke(t *testing.T) {
	_, args := destroyFixture(t)
	for _, test := range []struct {
		answer  string
		wantErr bool
	}{{"no\n", false}, {"\n", false}, {"   \n", false}, {"yes\n", true}, {"OK\n", true},
		{"ok", true}, {"", true}, {strings.Repeat("x", 1025) + "\n", true}} {
		t.Run(fmt.Sprintf("%q", test.answer[:min(len(test.answer), 12)]), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := runDestroyClusterWithRuntime(context.Background(), args, &stdout, &stderr, destroyClusterRuntime{
				input: strings.NewReader(test.answer), interactive: true,
				execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
					t.Fatal("unexpected lifecycle invocation")
					return nil
				},
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestDestroyRejectsPipedOK(t *testing.T) {
	_, args := destroyFixture(t)
	var stdout, stderr bytes.Buffer
	err := runDestroyClusterWithRuntime(context.Background(), args, &stdout, &stderr, destroyClusterRuntime{
		input: strings.NewReader("ok\n"), interactive: false,
		execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
			t.Fatal("piped ok invoked lifecycle")
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "interactive terminal") || stdout.Len() != 0 {
		t.Fatalf("err=%v stdout=%s", err, &stdout)
	}
}

func TestDestroyRejectsUnsafeInputsBeforeConfirmation(t *testing.T) {
	root, args := destroyFixture(t)
	tests := [][]string{{}, {"demo-cluster"}, {"../demo-cluster"}, {"default"}, {"kube-system"},
		{"demo;touch /tmp/never"}, {strings.Repeat("a", 64)},
		append(append([]string{}, args...), "--yes"),
		append(append([]string{}, args...), "--force"),
		append(append([]string{}, args...), "--confirm", "yes"),
		append(append([]string{}, args...), "another-cluster"),
		append(append([]string{}, args...), "--cluster-dir", filepath.Join(root, "wrong-name")),
		append(append([]string{}, args...), "--lifecycle-root", filepath.Join(root, "missing")),
		append(append([]string{}, args...), "--provider-kubeconfig", root),
		append(append([]string{}, args...), "--provider-kubeconfig", filepath.Join(root, "management.yaml")),
	}
	for _, argv := range tests {
		var stdout, stderr bytes.Buffer
		err := runDestroyClusterWithRuntime(context.Background(), argv, &stdout, &stderr, destroyClusterRuntime{
			input: strings.NewReader("ok\n"), interactive: true,
			execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
				t.Fatal("invalid input invoked lifecycle")
				return nil
			},
		})
		if err == nil || stdout.Len() != 0 {
			t.Fatalf("unsafe args accepted: %v err=%v stdout=%s", argv, err, &stdout)
		}
	}
}

func TestDestroyCancellationDuringPromptNeverInvokes(t *testing.T) {
	_, args := destroyFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- runDestroyClusterWithRuntime(ctx, args, &stdout, &stderr, destroyClusterRuntime{
			input: reader, interactive: true,
			execute: func(context.Context, string, []string, io.Writer, io.Writer) error {
				return errors.New("must not execute")
			},
		})
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled prompt did not return")
	}
}

func TestDestroyExecFailureIsNotRetriedAndKeepsExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake executable")
	}
	root, args := destroyFixture(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "python3"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var stdout, stderr bytes.Buffer
	calls := 0
	err := runDestroyClusterWithRuntime(context.Background(), args, &stdout, &stderr, destroyClusterRuntime{
		input: strings.NewReader("ok\n"), interactive: true,
		execute: func(ctx context.Context, dir string, argv []string, out, errOut io.Writer) error {
			calls++
			return executeLifecycleTeardown(ctx, dir, argv, out, errOut)
		},
	})
	var exit *exec.ExitError
	if !errors.As(err, &exit) || calls != 1 || cliExitCode(err) != 7 {
		t.Fatalf("err=%v calls=%d exitCode=%d", err, calls, cliExitCode(err))
	}
	if !strings.Contains(stdout.String(), filepath.Join(root, "scripts", "talos_golden_lifecycle.py")) ||
		!strings.Contains(err.Error(), "incomplete or interrupted") {
		t.Fatalf("lost arguments/outcome: %s %v", &stdout, err)
	}
	if cliExitCode(errors.New("ordinary CLI validation error")) != 2 {
		t.Fatal("existing CLI validation exit status changed")
	}
	if cliExitCode(exit) != 2 {
		t.Fatal("child exit status leaked into existing command error semantics")
	}
}
