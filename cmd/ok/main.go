package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/executor"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	ledgerNamespace = "openkubes-execution-system"
	stageRunTimeout = 10 * time.Minute
)

var (
	version                 = "0.0.0-dev"
	revision                = "unknown"
	stageReceiptFlagPattern = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
)

var materializeSubmissionStagePackage = func(config runner.SubmissionStagePackageConfig) ([]byte, runner.SubmissionStagePackageReceipt, error) {
	packaged, err := runner.BuildSubmissionStagePackage(config)
	if err != nil {
		return nil, runner.SubmissionStagePackageReceipt{}, err
	}
	raw, err := packaged.Bytes()
	if err != nil {
		return nil, runner.SubmissionStagePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var prepareSubmissionStageLaunch = func(config runner.SubmissionStageLaunchMaterialConfig) (stageLaunchPreparation, error) {
	material, err := runner.BuildSubmissionStageLaunchMaterial(config)
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return stageLaunchPreparation{}, err
	}
	return stageLaunchPreparation{
		Format: "ok147-submission-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

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

type stageLaunchPreparation struct {
	Format          string                                       `json:"format"`
	State           string                                       `json:"state"`
	Material        runner.SubmissionStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.SubmissionStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                         `json:"mutationAllowed"`
}

type receiptFlags []string

func (values *receiptFlags) String() string { return strings.Join(*values, ",") }

func (values *receiptFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type stageBundleFlags struct {
	expectedStage                                                 *string
	planPath, contractNamespace, contractName                     *string
	intentRevision, enablementRevision, platformRevision          *string
	executionFixture                                              *string
	infrastructureAuthority, managementAuthority, gitOpsAuthority *string
	grantPath, grantKeyPath, projectionManifest, projectionRoot   *string
	evaluationTime                                                *string
	receipts                                                      receiptFlags
	receiptPrefix, receiptPrefixDigest                            *string
}

func addStageBundleFlags(flags *flag.FlagSet) *stageBundleFlags {
	values := &stageBundleFlags{}
	values.expectedStage = flags.String("expected-stage", "", "independently expected Contract-to-CAPI stage")
	values.planPath = flags.String("plan", "", "path to the bounded staged execution plan")
	values.contractNamespace = flags.String("contract-namespace", "", "expected Contract namespace")
	values.contractName = flags.String("contract-name", "", "expected Contract name")
	values.intentRevision = flags.String("intent-revision", "", "expected normalized Contract revision R")
	values.enablementRevision = flags.String("enablement-revision", "", "expected Enablement revision E")
	values.platformRevision = flags.String("platform-revision", "", "expected Platform revision P")
	values.executionFixture = flags.String("execution-fixture", "", "expected execution FixtureDigest")
	values.infrastructureAuthority = flags.String("infrastructure-authority", "", "expected infrastructure authority identity")
	values.managementAuthority = flags.String("management-authority", "", "expected management authority identity")
	values.gitOpsAuthority = flags.String("gitops-authority", "", "expected GitOps authority identity")
	flags.Var(&values.receipts, "receipt", "ordered canonical predecessor receipt as PATH@sha256:<digest>; repeat for each receipt")
	values.receiptPrefix = flags.String("receipt-prefix", "", "path to a digest-bound ordered receipt-prefix manifest")
	values.receiptPrefixDigest = flags.String("receipt-prefix-digest", "", "expected SHA-256 digest of the receipt-prefix manifest")
	values.grantPath = flags.String("grant", "", "path to the signed single-stage grant")
	values.grantKeyPath = flags.String("grant-key", "", "path to the trusted stage-authority public key")
	values.projectionManifest = flags.String("projection-manifest", "", "path to the immutable projection manifest")
	values.projectionRoot = flags.String("projection-root", "", "directory containing projection artifacts (defaults to manifest directory)")
	values.evaluationTime = flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	return values
}

func (values *stageBundleFlags) config() (runner.SubmissionStageBundleConfig, error) {
	required := []struct {
		name  string
		value string
	}{
		{"--expected-stage", *values.expectedStage},
		{"--plan", *values.planPath}, {"--contract-namespace", *values.contractNamespace}, {"--contract-name", *values.contractName},
		{"--intent-revision", *values.intentRevision}, {"--enablement-revision", *values.enablementRevision}, {"--platform-revision", *values.platformRevision},
		{"--execution-fixture", *values.executionFixture}, {"--infrastructure-authority", *values.infrastructureAuthority},
		{"--management-authority", *values.managementAuthority}, {"--gitops-authority", *values.gitOpsAuthority},
		{"--grant", *values.grantPath}, {"--grant-key", *values.grantKeyPath}, {"--projection-manifest", *values.projectionManifest}, {"--evaluation-time", *values.evaluationTime},
	}
	for _, input := range required {
		if input.value == "" {
			return runner.SubmissionStageBundleConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	at, err := time.Parse(time.RFC3339, *values.evaluationTime)
	if err != nil {
		return runner.SubmissionStageBundleConfig{}, fmt.Errorf("parse evaluation time: %w", err)
	}
	providedPrefix := countNonEmpty(*values.receiptPrefix, *values.receiptPrefixDigest)
	if providedPrefix != 0 && (providedPrefix != 2 || len(values.receipts) != 0) {
		return runner.SubmissionStageBundleConfig{}, errors.New("--receipt-prefix and --receipt-prefix-digest must be provided together and cannot be combined with --receipt")
	}
	var receipts []runner.StageReceiptSource
	if providedPrefix == 2 {
		receipts, err = runner.LoadStageReceiptPrefix(*values.receiptPrefix, *values.receiptPrefixDigest)
		if err != nil {
			return runner.SubmissionStageBundleConfig{}, err
		}
	} else {
		receipts = make([]runner.StageReceiptSource, 0, len(values.receipts))
		for _, value := range values.receipts {
			if !stageReceiptFlagPattern.MatchString(value) {
				return runner.SubmissionStageBundleConfig{}, errors.New("receipt must use PATH@sha256:<64 lowercase hex> format")
			}
			separator := strings.LastIndex(value, "@sha256:")
			receipts = append(receipts, runner.StageReceiptSource{Path: value[:separator], Digest: value[separator+1:]})
		}
	}
	return runner.SubmissionStageBundleConfig{
		ExpectedStageID: *values.expectedStage, PlanPath: *values.planPath,
		PlanExpected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: *values.contractNamespace, Name: *values.contractName},
			IntentRevision:   *values.intentRevision, EnablementRevision: *values.enablementRevision,
			PlatformRevision: *values.platformRevision, ExecutionFixture: *values.executionFixture,
			InfrastructureAuthority: *values.infrastructureAuthority, ManagementAuthority: *values.managementAuthority, GitOpsAuthority: *values.gitOpsAuthority,
		},
		Receipts: receipts, GrantPath: *values.grantPath, GrantPublicKeyPath: *values.grantKeyPath,
		ProjectionManifestPath: *values.projectionManifest, ProjectionRoot: *values.projectionRoot, EvaluationTime: at,
	}, nil
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

var executeSubmissionStage = func(ctx context.Context, bundleConfig runner.SubmissionStageBundleConfig, runtimeConfig runner.SubmissionStageRuntimeConfig) (execution.StagedOperationReceipt, error) {
	bundle, err := runner.LoadSubmissionStageBundle(bundleConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	decision, err := bundle.Decision()
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	authorityIdentity, err := submissionStageAuthority(decision, bundleConfig.PlanExpected)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	runtimeConfig.Authority.AuthorityIdentity = authorityIdentity
	bound, err := bundle.Open(runtimeConfig)
	if err != nil {
		return execution.StagedOperationReceipt{}, err
	}
	return bound.Run(ctx)
}

func submissionStageAuthority(decision stagecursor.Decision, expected stageplan.Expected) (string, error) {
	switch decision.Authority {
	case "infrastructure":
		return expected.InfrastructureAuthority, nil
	case "management":
		return expected.ManagementAuthority, nil
	default:
		return "", errors.New("selected stage has no supported Kubernetes submission authority")
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	return runContext(context.Background(), arguments, stdout, stderr)
}

func runContext(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
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
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" {
		return runClusterStageRun(ctx, arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "package" {
		return runClusterStagePackage(arguments[3:], stdout, stderr)
	}
	if len(arguments) >= 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "launch" && arguments[3] == "prepare" {
		return runClusterStageLaunchPrepare(arguments[4:], stdout, stderr)
	}
	return errors.New("usage: ok cluster create ... | ok cluster stage inspect ... | ok cluster stage run ... | ok cluster stage package ... | ok cluster stage launch prepare ...")
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
	bundleFlags := addStageBundleFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	inspection, err := inspectSubmissionStage(bundleConfig)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inspection)
}

func runClusterStageRun(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	execute := flags.Bool("execute", false, "claim and execute exactly the selected authorized stage")
	ledgerAPIEndpoint := flags.String("ledger-api-endpoint", "", "TLS Kubernetes API endpoint for the durable ledger")
	ledgerTokenFile := flags.String("ledger-token-file", "", "path to the short-lived ledger token")
	ledgerCAFile := flags.String("ledger-ca-file", "", "path to the ledger Kubernetes API CA bundle")
	authorityAPIEndpoint := flags.String("authority-api-endpoint", "", "TLS Kubernetes API endpoint for the selected write authority")
	authorityTokenFile := flags.String("authority-token-file", "", "path to the selected short-lived write-authority token")
	authorityCAFile := flags.String("authority-ca-file", "", "path to the selected authority Kubernetes API CA bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("stage mutation requires explicit --execute")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct {
		name, value string
	}{
		{"--ledger-api-endpoint", *ledgerAPIEndpoint}, {"--ledger-token-file", *ledgerTokenFile}, {"--ledger-ca-file", *ledgerCAFile},
		{"--authority-api-endpoint", *authorityAPIEndpoint}, {"--authority-token-file", *authorityTokenFile}, {"--authority-ca-file", *authorityCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageRunTimeout)
	defer cancel()
	receipt, runErr := executeSubmissionStage(boundedContext, bundleConfig, runner.SubmissionStageRuntimeConfig{
		Ledger: runner.KubernetesLedgerConfig{
			Endpoint: *ledgerAPIEndpoint, Namespace: ledgerNamespace, TokenFile: *ledgerTokenFile, CAFile: *ledgerCAFile,
		},
		Authority: runner.KubernetesAuthorityConfig{
			Endpoint: *authorityAPIEndpoint, TokenFile: *authorityTokenFile, CAFile: *authorityCAFile,
		},
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return runErr
}

func runClusterStagePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	jobTemplate := flags.String("job-template", "", "path to the bounded submission-stage Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified ConfigMap/Job/NetworkPolicy package")
	runID := flags.String("run-id", "", "bounded OK-147 Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "externally materialized ledger credential Secret name")
	authorityAPIURL := flags.String("authority-api-url", "", "exact selected-authority HTTPS IP endpoint")
	authorityAPICIDR := flags.String("authority-api-cidr", "", "single-address selected-authority CIDR")
	authorityCredentialSecret := flags.String("authority-credential-secret", "", "externally materialized authority credential Secret name")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output}, {"--run-id", *runID}, {"--image", *imageDigest},
		{"--input-configmap", *inputConfigMap}, {"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR},
		{"--ledger-credential-secret", *ledgerCredentialSecret}, {"--authority-api-url", *authorityAPIURL},
		{"--authority-api-cidr", *authorityAPICIDR}, {"--authority-credential-secret", *authorityCredentialSecret},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read Job template: %w", err)
	}
	raw, receipt, err := materializeSubmissionStagePackage(runner.SubmissionStagePackageConfig{
		Bundle: bundleConfig, JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		AuthorityAPIURL: *authorityAPIURL, AuthorityAPICIDR: *authorityAPICIDR, AuthorityCredentialSecret: *authorityCredentialSecret,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

type stageLaunchCredentialFlags struct {
	authority, tokenFile, tokenDigest, caFile, caDigest, evidenceDigest *string
	issuer, subject, audiences, issuedAt, expiresAt                     *string
}

func addStageLaunchCredentialFlags(flags *flag.FlagSet, prefix, description string) *stageLaunchCredentialFlags {
	values := &stageLaunchCredentialFlags{}
	values.authority = flags.String(prefix+"-authority", "", description+" authority identity")
	values.tokenFile = flags.String(prefix+"-token-file", "", description+" bounded token file")
	values.tokenDigest = flags.String(prefix+"-token-digest", "", description+" expected token digest")
	values.caFile = flags.String(prefix+"-ca-file", "", description+" bounded CA file")
	values.caDigest = flags.String(prefix+"-ca-digest", "", description+" expected CA digest")
	values.evidenceDigest = flags.String(prefix+"-tokenrequest-evidence-digest", "", description+" TokenRequest evidence digest")
	values.issuer = flags.String(prefix+"-issuer", "", description+" expected token issuer")
	values.subject = flags.String(prefix+"-subject", "", description+" expected ServiceAccount subject")
	values.audiences = flags.String(prefix+"-audiences", "", description+" comma-separated exact token audiences")
	values.issuedAt = flags.String(prefix+"-issued-at", "", description+" exact token issued-at time")
	values.expiresAt = flags.String(prefix+"-expires-at", "", description+" exact token expiration time")
	return values
}

func (values *stageLaunchCredentialFlags) source(prefix string) (runner.SubmissionStageCredentialSource, error) {
	required := []struct{ name, value string }{
		{"--" + prefix + "-authority", *values.authority}, {"--" + prefix + "-token-file", *values.tokenFile},
		{"--" + prefix + "-token-digest", *values.tokenDigest}, {"--" + prefix + "-ca-file", *values.caFile},
		{"--" + prefix + "-ca-digest", *values.caDigest}, {"--" + prefix + "-tokenrequest-evidence-digest", *values.evidenceDigest},
		{"--" + prefix + "-issuer", *values.issuer}, {"--" + prefix + "-subject", *values.subject},
		{"--" + prefix + "-audiences", *values.audiences}, {"--" + prefix + "-issued-at", *values.issuedAt},
		{"--" + prefix + "-expires-at", *values.expiresAt},
	}
	for _, input := range required {
		if input.value == "" {
			return runner.SubmissionStageCredentialSource{}, fmt.Errorf("%s is required", input.name)
		}
	}
	issuedAt, err := time.Parse(time.RFC3339, *values.issuedAt)
	if err != nil {
		return runner.SubmissionStageCredentialSource{}, fmt.Errorf("parse %s issued-at: %w", prefix, err)
	}
	expiresAt, err := time.Parse(time.RFC3339, *values.expiresAt)
	if err != nil {
		return runner.SubmissionStageCredentialSource{}, fmt.Errorf("parse %s expires-at: %w", prefix, err)
	}
	audiences := strings.Split(*values.audiences, ",")
	for _, audience := range audiences {
		if audience == "" || strings.TrimSpace(audience) != audience {
			return runner.SubmissionStageCredentialSource{}, fmt.Errorf("--%s-audiences must contain exact non-empty values", prefix)
		}
	}
	return runner.SubmissionStageCredentialSource{
		AuthorityIdentity: *values.authority, TokenFile: *values.tokenFile, TokenDigest: *values.tokenDigest,
		CAFile: *values.caFile, CABundleDigest: *values.caDigest, TokenRequestEvidenceDigest: *values.evidenceDigest,
		ExpectedIssuer: *values.issuer, ExpectedSubject: *values.subject, ExpectedAudiences: audiences,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}, nil
}

func runClusterStageLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	bundleFlags := addStageBundleFlags(flags)
	jobTemplate := flags.String("job-template", "", "path to the bounded submission-stage Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	runID := flags.String("run-id", "", "bounded OK-147 Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	authorityAPIURL := flags.String("authority-api-url", "", "exact selected-authority HTTPS IP endpoint")
	authorityAPICIDR := flags.String("authority-api-cidr", "", "single-address selected-authority CIDR")
	authorityCredentialSecret := flags.String("authority-credential-secret", "", "authority credential Secret name")
	materializedAt := flags.String("credential-materialized-at", "", "exact credential materialization time")
	ledgerCredential := addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	authorityCredential := addStageLaunchCredentialFlags(flags, "authority-job", "selected-authority Job credential")
	runtimeManifest := flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	runtimeManifestDigest := flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	installerAPIEndpoint := flags.String("installer-api-endpoint", "", "exact management installer HTTPS IP endpoint")
	installerCADigest := flags.String("installer-ca-digest", "", "expected management installer CA digest")
	installerTokenDigest := flags.String("installer-token-digest", "", "private expected management installer token digest")
	installerEvidenceDigest := flags.String("installer-tokenrequest-evidence-digest", "", "management installer TokenRequest evidence digest")
	preparedAt := flags.String("prepared-at", "", "exact launch candidate preparation time")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	bundleConfig, err := bundleFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--run-id", *runID}, {"--image", *imageDigest},
		{"--input-configmap", *inputConfigMap}, {"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR},
		{"--ledger-credential-secret", *ledgerCredentialSecret}, {"--authority-api-url", *authorityAPIURL},
		{"--authority-api-cidr", *authorityAPICIDR}, {"--authority-credential-secret", *authorityCredentialSecret},
		{"--credential-materialized-at", *materializedAt}, {"--runtime-manifest", *runtimeManifest},
		{"--runtime-manifest-digest", *runtimeManifestDigest}, {"--installer-api-endpoint", *installerAPIEndpoint},
		{"--installer-ca-digest", *installerCADigest}, {"--installer-token-digest", *installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *installerEvidenceDigest}, {"--prepared-at", *preparedAt},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	materializationTime, err := time.Parse(time.RFC3339, *materializedAt)
	if err != nil {
		return fmt.Errorf("parse credential materialization time: %w", err)
	}
	candidateTime, err := time.Parse(time.RFC3339, *preparedAt)
	if err != nil {
		return fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := ledgerCredential.source("ledger-job")
	if err != nil {
		return err
	}
	authoritySource, err := authorityCredential.source("authority-job")
	if err != nil {
		return err
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*runtimeManifest, 128*1024)
	if err != nil {
		return fmt.Errorf("read runtime manifest: %w", err)
	}
	preparation, err := prepareSubmissionStageLaunch(runner.SubmissionStageLaunchMaterialConfig{
		Package: runner.SubmissionStagePackageConfig{
			Bundle: bundleConfig, JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
			RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap,
			LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
			AuthorityAPIURL: *authorityAPIURL, AuthorityAPICIDR: *authorityAPICIDR, AuthorityCredentialSecret: *authorityCredentialSecret,
		},
		MaterializationTime: materializationTime, Ledger: ledgerSource, SelectedAuthority: authoritySource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *installerAPIEndpoint, CABundleDigest: *installerCADigest,
			InstallerTokenDigest: *installerTokenDigest, InstallerCredentialEvidenceDigest: *installerEvidenceDigest,
			PreparedAt: candidateTime,
		},
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func readBoundedLocalFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("local file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() <= 0 || opened.Size() > maximum {
		return nil, errors.New("local file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded local file")
	}
	return raw, nil
}

func writeNewLocalFile(path string, raw []byte) (err error) {
	if path == "" || len(raw) == 0 {
		return errors.New("non-empty output path and package are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err = file.Write(raw); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
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
