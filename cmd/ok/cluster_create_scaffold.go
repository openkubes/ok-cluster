package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const clusterCreateScaffoldReceiptFormat = "ok-cli-cluster-create-scaffold/v1"

var clusterCreateNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)

type clusterCreateScaffoldReceipt struct {
	Format          string   `json:"format"`
	State           string   `json:"state"`
	ContractName    string   `json:"contractName"`
	OutputDirectory string   `json:"outputDirectory"`
	Files           []string `json:"files"`
	APIContacted    bool     `json:"apiContacted"`
	MutationAllowed bool     `json:"mutationAllowed"`
	NextAction      string   `json:"nextAction"`
}

func runClusterCreateScaffold(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster create scaffold", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("name", "", "new cluster and Contract name")
	output := flags.String("output", "", "new private directory to create")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !clusterCreateNamePattern.MatchString(*name) || len(*name) > 63 {
		return errors.New("--name must be a DNS label of at most 63 characters")
	}
	if *output == "" {
		return errors.New("--output is required and must name a new directory")
	}
	abs, err := filepath.Abs(*output)
	if err != nil || filepath.Clean(abs) == string(filepath.Separator) {
		return errors.New("--output path is invalid")
	}
	if _, err := os.Lstat(abs); err == nil {
		return errors.New("--output already exists; refusing to reuse or overwrite it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect --output: %w", err)
	}
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("--output parent must be an existing directory")
	}
	if err := os.Mkdir(abs, 0o700); err != nil {
		return fmt.Errorf("create private scaffold directory: %w", err)
	}
	planPath := filepath.Join(abs, "staged-plan.json")
	manifestPath := filepath.Join(abs, "full-run-manifest.json")
	if err := writeExclusivePrivateFile(planPath, func(writer io.Writer) error {
		return writeClusterCreatePlanTemplate(writer, *name, *name)
	}); err != nil {
		return err
	}
	if err := writeExclusivePrivateFile(manifestPath, func(writer io.Writer) error {
		return writeClusterCreateManifestTemplate(writer, *name, *name, abs)
	}); err != nil {
		return err
	}
	receipt := clusterCreateScaffoldReceipt{
		Format: clusterCreateScaffoldReceiptFormat, State: "SCAFFOLDED", ContractName: *name,
		OutputDirectory: abs, Files: []string{planPath, manifestPath}, APIContacted: false, MutationAllowed: false,
		NextAction: "supply authoritative artifacts and private inputs, then run ok cluster create --file " + manifestPath + " --dry-run",
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func writeExclusivePrivateFile(path string, write func(io.Writer) error) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private scaffold file: %w", err)
	}
	if err := write(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("write private scaffold file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private scaffold file: %w", err)
	}
	return nil
}
