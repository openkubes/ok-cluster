package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// Produce desired Contract bytes, never credentials, grants or previous R/F.
// The caller must run the existing canonicalizer and projection verifier.
func compileClusterIntentContract(ctx context.Context, intent clusterIntent, root, profiles string, stderr io.Writer) ([]byte, map[string]string, error) {
	raw, err := json.Marshal(intent)
	if err != nil {
		return nil, nil, err
	}
	command := exec.CommandContext(ctx, "python3", "-B", filepath.Join(root, "scripts", "compile_cluster_contract.py"), "--ok-linux-path", profiles)
	command.Dir = root
	command.Stdin = bytes.NewReader(raw)
	command.Stderr = stderr
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, nil, errors.New("reviewed profile Contract compilation failed; no authority or runner opened")
	}
	var compiled struct {
		Contract json.RawMessage   `json:"contract"`
		Sources  map[string]string `json:"sourceDigests"`
	}
	if output.Len() > 1024*1024 || jsonstrict.Decode(output.Bytes(), &compiled) != nil || len(compiled.Contract) == 0 || len(compiled.Sources) != 6 {
		return nil, nil, errors.New("invalid offline Contract compiler output")
	}
	for _, key := range []string{"contractRecipe", "runnerRecipe", "compiler", "rendererAdapter", "resolver", "okLinuxProfile"} {
		if !sha256DigestPattern.MatchString(compiled.Sources[key]) {
			return nil, nil, errors.New("missing Contract source digest")
		}
	}
	return compiled.Contract, compiled.Sources, nil
}
