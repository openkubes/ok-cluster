package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

func promptConfigPaths(ctx context.Context, config *localCLIConfig, reader *bufio.Reader, output io.Writer) error {
	if _, err := fmt.Fprintln(output, "Local path setup only; no kubeconfig contents are read and no cluster is contacted.\nEnter literal paths, not shell commands. All five paths are required."); err != nil {
		return err
	}
	for _, field := range []struct {
		label string
		value *string
	}{
		{"Trusted ok-cluster checkout", &config.LifecycleRoot}, {"ok-linux profile checkout", &config.OKLinuxPath},
		{"Parent of rendered clusters/evidence", &config.ClustersDir}, {"Management kubeconfig file", &config.ManagementKubeconfig},
		{"Separate provider kubeconfig file", &config.ProviderKubeconfig},
	} {
		if *field.value != "" {
			continue
		}
		if _, err := fmt.Fprintf(output, "%s: ", field.label); err != nil {
			return err
		}
		line, err := readConfigPromptLine(ctx, reader)
		if err != nil {
			return err
		}
		value := strings.TrimSpace(line)
		if value == "" {
			return errors.New("all paths are required; configuration not saved")
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return errors.New("control characters are not accepted in prompted paths; configuration not saved")
		}
		if value == "~" || strings.HasPrefix(value, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			if value == "~" {
				value = home
			} else {
				value = filepath.Join(home, strings.TrimPrefix(value, "~/"))
			}
		}
		*field.value = value
	}
	return nil
}

func confirmConfigPaths(ctx context.Context, config localCLIConfig, path string, reader *bufio.Reader, output io.Writer) error {
	if _, err := fmt.Fprintf(output, "\nReview local paths:\n  Config: %q\n  Lifecycle: %q\n  ok-linux: %q\n  Clusters/evidence: %q\n  Management kubeconfig: %q\n  Provider kubeconfig: %q\nSave these paths? Type ok or no [no]: ",
		path, config.LifecycleRoot, config.OKLinuxPath, config.ClustersDir, config.ManagementKubeconfig, config.ProviderKubeconfig); err != nil {
		return err
	}
	line, err := readConfigPromptLine(ctx, reader)
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "ok" {
		return errors.New("configuration not saved (default is no)")
	}
	return nil
}

func readConfigPromptLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	type response struct {
		line string
		err  error
	}
	result := make(chan response, 1)
	go func() { line, err := reader.ReadSlice('\n'); result <- response{string(line), err} }()
	select {
	case <-ctx.Done():
		return "", errors.New("configuration setup interrupted; not saved")
	case value := <-result:
		if errors.Is(value.err, bufio.ErrBufferFull) {
			return "", errors.New("configuration answer too long; not saved")
		}
		if value.err != nil {
			return "", errors.New("configuration setup ended before confirmation; not saved")
		}
		if len(value.line) > 4096 {
			return "", errors.New("configuration answer too long; not saved")
		}
		return strings.TrimSuffix(strings.TrimSuffix(value.line, "\n"), "\r"), nil
	}
}
