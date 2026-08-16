package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	ledgerNamespace = "openkubes-execution-system"
)

var (
	version                 = "0.0.0-dev"
	revision                = "unknown"
	stageReceiptFlagPattern = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
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

type stageInspection struct {
	Format             string               `json:"format"`
	Decision           stagecursor.Decision `json:"decision"`
	AuthorizationState string               `json:"authorizationState"`
	MutationAllowed    bool                 `json:"mutationAllowed"`
}

type receiptFlags []string

func (values *receiptFlags) String() string { return strings.Join(*values, ",") }

func (values *receiptFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

var inspectSubmissionStage = func(config runner.SubmissionStageBundleConfig) (stageInspection, error) {
	bundle, err := runner.LoadSubmissionStageBundle(config)
	if err != nil {
		return stageInspection{}, err
	}
	decision, err := bundle.Decision()
	if err != nil {
		return stageInspection{}, err
	}
	return stageInspection{
		Format: "ok147-stage-inspection/v1", Decision: decision,
		AuthorizationState: "VERIFIED", MutationAllowed: false,
	}, nil
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
	if len(arguments) >= 2 && arguments[0] == "cluster" && arguments[1] == "create" {
		return runClusterCreate(arguments[2:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "inspect" {
		return runClusterStageInspect(arguments[3:], stdout, stderr)
	}
	return errors.New("usage: ok cluster create ... | ok cluster stage inspect ...")
}

func runClusterCreate(arguments []string, stdout, stderr io.Writer) error {
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
	if err := flags.Parse(arguments); err != nil {
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

func runClusterStageInspect(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "path to the bounded staged execution plan")
	contractNamespace := flags.String("contract-namespace", "", "expected Contract namespace")
	contractName := flags.String("contract-name", "", "expected Contract name")
	intentRevision := flags.String("intent-revision", "", "expected normalized Contract revision R")
	enablementRevision := flags.String("enablement-revision", "", "expected Enablement revision E")
	platformRevision := flags.String("platform-revision", "", "expected Platform revision P")
	executionFixture := flags.String("execution-fixture", "", "expected execution FixtureDigest")
	infrastructureAuthority := flags.String("infrastructure-authority", "", "expected infrastructure authority identity")
	managementAuthority := flags.String("management-authority", "", "expected management authority identity")
	gitOpsAuthority := flags.String("gitops-authority", "", "expected GitOps authority identity")
	var receiptValues receiptFlags
	flags.Var(&receiptValues, "receipt", "ordered canonical predecessor receipt as PATH@sha256:<digest>; repeat for each receipt")
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	projectionManifest := flags.String("projection-manifest", "", "path to the immutable projection manifest")
	projectionRoot := flags.String("projection-root", "", "directory containing projection artifacts (defaults to manifest directory)")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	required := []struct {
		name  string
		value string
	}{
		{"--plan", *planPath}, {"--contract-namespace", *contractNamespace}, {"--contract-name", *contractName},
		{"--intent-revision", *intentRevision}, {"--enablement-revision", *enablementRevision}, {"--platform-revision", *platformRevision},
		{"--execution-fixture", *executionFixture}, {"--infrastructure-authority", *infrastructureAuthority},
		{"--management-authority", *managementAuthority}, {"--gitops-authority", *gitOpsAuthority},
		{"--grant", *grantPath}, {"--grant-key", *grantKeyPath}, {"--projection-manifest", *projectionManifest}, {"--evaluation-time", *evaluationTime},
	}
	for _, input := range required {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	receipts := make([]runner.StageReceiptSource, 0, len(receiptValues))
	for _, value := range receiptValues {
		if !stageReceiptFlagPattern.MatchString(value) {
			return errors.New("receipt must use PATH@sha256:<64 lowercase hex> format")
		}
		separator := strings.LastIndex(value, "@sha256:")
		receipts = append(receipts, runner.StageReceiptSource{Path: value[:separator], Digest: value[separator+1:]})
	}
	inspection, err := inspectSubmissionStage(runner.SubmissionStageBundleConfig{
		PlanPath: *planPath,
		PlanExpected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: *contractNamespace, Name: *contractName},
			IntentRevision:   *intentRevision, EnablementRevision: *enablementRevision,
			PlatformRevision: *platformRevision, ExecutionFixture: *executionFixture,
			InfrastructureAuthority: *infrastructureAuthority, ManagementAuthority: *managementAuthority, GitOpsAuthority: *gitOpsAuthority,
		},
		Receipts: receipts, GrantPath: *grantPath, GrantPublicKeyPath: *grantKeyPath,
		ProjectionManifestPath: *projectionManifest, ProjectionRoot: *projectionRoot, EvaluationTime: at,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inspection)
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
