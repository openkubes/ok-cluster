package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalConfigInteractiveConfirmation(t *testing.T) {
	for _, answer := range []string{"ok\n", "no\n", "\n", "yes\n", "ok"} {
		t.Run(strings.ReplaceAll(answer, "\n", "newline"), func(t *testing.T) {
			config, _ := configFixture(t)
			path := filepath.Join(t.TempDir(), "not-created", "config.json")
			input := strings.Join([]string{config.LifecycleRoot, config.OKLinuxPath, config.ClustersDir, config.ManagementKubeconfig, config.ProviderKubeconfig}, "\n") + "\n" + answer
			var stdout, stderr bytes.Buffer
			err := runConfigWithRuntime(context.Background(), []string{"init", "--config", path}, &stdout, &stderr, configInitRuntime{strings.NewReader(input), true})
			if answer == "ok\n" {
				loaded, loadErr := loadLocalConfig(path)
				if err != nil || loadErr != nil || loaded != config {
					t.Fatalf("err=%v load=%v config=%+v", err, loadErr, loaded)
				}
			} else if err == nil {
				t.Fatal("accepted unconfirmed setup")
			} else if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("cancelled setup created configuration directory")
			}
		})
	}
}

func TestLocalConfigInteractivePartialAndNonTerminal(t *testing.T) {
	for _, terminal := range []bool{true, false} {
		_, args := configFixture(t)
		path := filepath.Join(t.TempDir(), "private", "config.json")
		args = append(args[1:], "--interactive", "--config", path)
		var stdout, stderr bytes.Buffer
		err := runConfigWithRuntime(context.Background(), args, &stdout, &stderr, configInitRuntime{strings.NewReader("ok\n"), terminal})
		if (err == nil) != terminal {
			t.Fatalf("terminal=%v err=%v", terminal, err)
		}
	}
	config, _ := configFixture(t)
	path := filepath.Join(t.TempDir(), "private", "config.json")
	var stdout, stderr bytes.Buffer
	input := strings.Join([]string{config.OKLinuxPath, config.ClustersDir, config.ManagementKubeconfig, config.ProviderKubeconfig, "ok", ""}, "\n")
	err := runConfigWithRuntime(context.Background(), []string{"init", "--interactive", "--lifecycle-root", config.LifecycleRoot, "--config", path}, &stdout, &stderr, configInitRuntime{strings.NewReader(input), true})
	if err != nil || strings.Contains(stderr.String(), "Trusted ok-cluster checkout: ") {
		t.Fatalf("err=%v prompts=%s", err, &stderr)
	}
}

func TestLocalConfigInteractiveNoInputOnExistingOrDisabled(t *testing.T) {
	_, args := configFixture(t)
	path := filepath.Join(privateConfigTestDir(t), "config.json")
	if err := os.WriteFile(path, []byte("preserve me"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{append(args[1:], "--interactive", "--config", path), {"init", "--interactive=false", "--config", filepath.Join(t.TempDir(), "missing.json")}, {"init", "--interactive", "--lifecycle-root=", "--config", filepath.Join(t.TempDir(), "missing.json")}} {
		var output bytes.Buffer
		if err := runConfigWithRuntime(context.Background(), args, &output, &output, configInitRuntime{panicConfigReader{}, true}); err == nil {
			t.Fatal("expected rejection")
		}
	}
	data, _ := os.ReadFile(path)
	if string(data) != "preserve me" {
		t.Fatal("existing configuration changed")
	}
}

type panicConfigReader struct{}

func (panicConfigReader) Read([]byte) (int, error) { panic("unexpected input read") }

func TestLocalConfigPromptBoundedAndCancelled(t *testing.T) {
	for _, input := range []string{strings.Repeat("x", 5000) + "\n", "", "\n", "bad\x1bpath\n"} {
		var config localCLIConfig
		if err := promptConfigPaths(context.Background(), &config, bufio.NewReaderSize(strings.NewReader(input), 4096), io.Discard); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	cancel()
	if _, err := readConfigPromptLine(ctx, bufio.NewReader(reader)); err == nil {
		t.Fatal("cancel ignored")
	}
	isolatedConfigHome(t)
	var config localCLIConfig
	err := promptConfigPaths(context.Background(), &config, bufio.NewReader(strings.NewReader(" ~ \n~/profiles\n~/clusters\n~/management\n~/provider\n")), io.Discard)
	if err != nil || config.LifecycleRoot != os.Getenv("HOME") || config.OKLinuxPath != filepath.Join(os.Getenv("HOME"), "profiles") {
		t.Fatalf("config=%+v err=%v", config, err)
	}
}
