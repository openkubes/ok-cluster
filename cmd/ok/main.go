package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openkubes/ok-cluster/internal/contract"
)

const version = "0.0.0-dev"

type createPlan struct {
	Format                  string            `json:"format"`
	Operation               string            `json:"operation"`
	ContractIdentity        contract.Identity `json:"contractIdentity"`
	ContractRevision        string            `json:"contractRevision"`
	CanonicalizationProfile string            `json:"canonicalizationProfile"`
	RawArtifactDigest       string            `json:"rawArtifactDigest"`
	SchemaDigest            string            `json:"schemaDigest"`
	AuthorizationState      string            `json:"authorizationState"`
	MutationAllowed         bool              `json:"mutationAllowed"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 1 && arguments[0] == "version" {
		fmt.Fprintln(stdout, version)
		return nil
	}
	if len(arguments) < 2 || arguments[0] != "cluster" || arguments[1] != "create" {
		return errors.New("usage: ok cluster create --contract PATH --schema PATH --dry-run")
	}
	flags := flag.NewFlagSet("ok cluster create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to the versioned cluster contract")
	schemaPath := flags.String("schema", "", "path to the contract test schema")
	dryRun := flags.Bool("dry-run", false, "validate and emit an immutable create plan without mutation")
	if err := flags.Parse(arguments[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*dryRun {
		return errors.New("the OK-147 MVP currently requires --dry-run; submission is not implemented")
	}
	if *contractPath == "" || *schemaPath == "" {
		return errors.New("--contract and --schema are required")
	}
	raw, err := os.ReadFile(*contractPath)
	if err != nil {
		return fmt.Errorf("read contract: %w", err)
	}
	schema, err := os.ReadFile(*schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
	result, err := contract.Canonicalize(raw, schema)
	if err != nil {
		return err
	}
	identity, err := contract.ContractIdentity(result.Normalized)
	if err != nil {
		return err
	}
	plan := createPlan{
		Format:                  "ok147-create-plan/v1",
		Operation:               "CreateCluster",
		ContractIdentity:        identity,
		ContractRevision:        result.NormalizedDigest,
		CanonicalizationProfile: result.CanonicalizationProfile,
		RawArtifactDigest:       result.RawArtifactDigest,
		SchemaDigest:            result.SchemaDigest,
		AuthorizationState:      "NOT_EVALUATED",
		MutationAllowed:         false,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}
