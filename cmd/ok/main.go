package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
)

const (
	ledgerNamespace = "openkubes-execution-system"
)

var (
	version  = "0.0.0-dev"
	revision = "unknown"
)

type createPlan struct {
	Format                  string                  `json:"format"`
	Operation               string                  `json:"operation"`
	ContractIdentity        contract.Identity       `json:"contractIdentity"`
	ContractRevision        string                  `json:"contractRevision"`
	CanonicalizationProfile string                  `json:"canonicalizationProfile"`
	RawArtifactDigest       string                  `json:"rawArtifactDigest"`
	SchemaDigest            string                  `json:"schemaDigest"`
	AuthorizationState      string                  `json:"authorizationState"`
	MutationAllowed         bool                    `json:"mutationAllowed"`
	Request                 *executor.CreateRequest `json:"request,omitempty"`
	RequestDigest           string                  `json:"requestDigest,omitempty"`
	Authorization           *authorization.Receipt  `json:"authorization,omitempty"`
	Ledger                  *ledger.Inspection      `json:"ledger,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 1 && arguments[0] == "version" {
		fmt.Fprintf(stdout, "%s %s\n", version, revision)
		return nil
	}
	if len(arguments) < 2 || arguments[0] != "cluster" || arguments[1] != "create" {
		return errors.New("usage: ok cluster create --contract PATH --schema PATH --dry-run [--projection-manifest PATH] [--authorization PATH --authorization-key PATH --evaluation-time RFC3339] [--ledger-inspect --ledger-api-endpoint URL --ledger-token-file PATH --ledger-ca-file PATH]")
	}
	flags := flag.NewFlagSet("ok cluster create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", "", "path to the versioned cluster contract")
	schemaPath := flags.String("schema", "", "path to the contract test schema")
	dryRun := flags.Bool("dry-run", false, "validate and emit an immutable create plan without mutation")
	projectionManifest := flags.String("projection-manifest", "", "path to an immutable projection manifest produced by the authoritative renderer")
	projectionRoot := flags.String("projection-root", "", "directory containing projection artifacts (defaults to manifest directory)")
	authorizationPath := flags.String("authorization", "", "path to a signed create authorization JSON document")
	authorizationKeyPath := flags.String("authorization-key", "", "path to the trusted base64-encoded raw Ed25519 public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 authorization evaluation time")
	ledgerInspect := flags.Bool("ledger-inspect", false, "read the exact durable grant state without claiming it")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to a projected short-lived ledger ServiceAccount token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the projected Kubernetes API CA bundle")
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
	if *projectionRoot != "" && *projectionManifest == "" {
		return errors.New("--projection-root requires --projection-manifest")
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
	if *projectionManifest != "" {
		binding, err := projection.Verify(*projectionManifest, *projectionRoot, result.NormalizedDigest, identity)
		if err != nil {
			return err
		}
		request, err := executor.NewCreateRequest(result, identity, binding)
		if err != nil {
			return err
		}
		requestDigest, err := executor.Digest(request)
		if err != nil {
			return fmt.Errorf("digest create request: %w", err)
		}
		plan.Format = "ok147-create-plan/v2"
		plan.Request = &request
		plan.RequestDigest = requestDigest
	}
	providedAuthorizationInputs := countNonEmpty(*authorizationPath, *authorizationKeyPath, *evaluationTime)
	var verifiedGrant authorization.VerifiedGrant
	if providedAuthorizationInputs != 0 {
		if plan.Request == nil {
			return errors.New("--authorization requires --projection-manifest")
		}
		if providedAuthorizationInputs != 3 {
			return errors.New("--authorization, --authorization-key, and --evaluation-time must be provided together")
		}
		authorizationRaw, err := os.ReadFile(*authorizationPath)
		if err != nil {
			return fmt.Errorf("read authorization: %w", err)
		}
		keyRaw, err := os.ReadFile(*authorizationKeyPath)
		if err != nil {
			return fmt.Errorf("read authorization key: %w", err)
		}
		at, err := time.Parse(time.RFC3339, *evaluationTime)
		if err != nil {
			return fmt.Errorf("parse evaluation time: %w", err)
		}
		grant, err := authorization.Verify(authorizationRaw, keyRaw, *plan.Request, at)
		if err != nil {
			return err
		}
		verifiedGrant = grant
		receipt := grant.Receipt()
		plan.AuthorizationState = "VERIFIED"
		plan.Authorization = &receipt
	}
	providedLedgerInputs := countNonEmpty(*ledgerAPIEndpoint, *ledgerTokenFile, *ledgerCAFile)
	if !*ledgerInspect && providedLedgerInputs != 0 {
		return errors.New("Kubernetes ledger inputs require --ledger-inspect")
	}
	if *ledgerInspect {
		if plan.Authorization == nil {
			return errors.New("--ledger-inspect requires a verified authorization")
		}
		if providedLedgerInputs != 3 {
			return errors.New("--ledger-api-endpoint, --ledger-token-file, and --ledger-ca-file must be provided together")
		}
		inspection, err := runner.InspectKubernetesLedger(context.Background(), verifiedGrant, runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		})
		if err != nil {
			return fmt.Errorf("inspect durable grant ledger: %w", err)
		}
		plan.Format = "ok147-create-plan/v3"
		plan.Ledger = &inspection
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(plan)
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}
