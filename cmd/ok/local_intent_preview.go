package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/digest"
)

// runLocalIntentPreview reads a bounded, local authoring file only.
// It is deliberately not an ADR-034 authoritative plan or authorization.
func runLocalIntentPreview(args []string, directory string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok preview", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var file string
	flags.StringVar(&file, "file", "", "explicit cluster authoring YAML (default: ./openkubes.yaml)")
	flags.StringVar(&file, "f", "", "alias of --file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("ok preview accepts only --file/-f")
	}
	if directory == "" {
		return errors.New("preview working directory is unavailable")
	}
	var count int
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "file" || f.Name == "f" {
			count++
		}
	})
	if count > 1 {
		return errors.New("select an authoring file exactly once")
	}
	if file == "" {
		if count > 0 {
			return errors.New("explicit --file must not be empty")
		}
		file = "openkubes.yaml"
	}
	// Resolve relative references only against the supplied current directory.
	// No parent-directory discovery, credentials, network access, or renderer.
	if !filepath.IsAbs(file) {
		file = filepath.Join(directory, file)
	}
	intent, err := readClusterIntent(file)
	if err != nil {
		return fmt.Errorf("local preview rejected authoring file: %w", err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	// This digest identifies normalized local intent only, NOT a canonical
	// authorized Contract revision, plan identity or an allocation reservation.
	result := struct {
		Format                string `json:"format"`
		State                 string `json:"state"`
		Name                  string `json:"name"`
		Profile               string `json:"profile"`
		Endpoint              string `json:"endpoint"`
		PodCIDR               string `json:"podCIDR"`
		ServiceCIDR           string `json:"serviceCIDR"`
		LocalIntentDigest     string `json:"localIntentDigest"`
		AuthorityVerified     bool   `json:"authorityVerified"`
		APIContacted          bool   `json:"apiContacted"`
		AuthorizationConsumed bool   `json:"authorizationConsumed"`
		MutationAllowed       bool   `json:"mutationAllowed"`
		NextAction            string `json:"nextAction"`
	}{
		Format: "ok-cli-local-intent-preview/v1", State: "LOCAL_VALIDATION_ONLY",
		Name: intent.Metadata.Name, Profile: intent.Spec.Profile,
		Endpoint: intent.Spec.Network.Endpoint,
		PodCIDR: intent.Spec.Network.PodCIDR, ServiceCIDR: intent.Spec.Network.ServiceCIDR,
		LocalIntentDigest: digest.SHA256(raw),
		NextAction: "no authoritative revision, authorization, collision check, or workload readiness has been established",
	}
	return json.NewEncoder(stdout).Encode(result)
}

func runPreviewCLI(args []string, stdout, stderr io.Writer) error {
	directory, err := os.Getwd()
	if err != nil {
		return err
	}
	return runLocalIntentPreview(args, directory, stdout, stderr)
}
