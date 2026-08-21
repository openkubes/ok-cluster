package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
)

var prepareTargetAccessStageLaunch = func(config runner.TargetAccessStageLaunchMaterialConfig) (targetAccessLaunchPreparation, error) {
	material, err := runner.BuildTargetAccessStageLaunchMaterial(config)
	if err != nil {
		return targetAccessLaunchPreparation{}, err
	}
	materialReceipt, err := material.Receipt()
	if err != nil {
		return targetAccessLaunchPreparation{}, err
	}
	candidateReceipt, err := material.CandidateReceipt()
	if err != nil {
		return targetAccessLaunchPreparation{}, err
	}
	return targetAccessLaunchPreparation{
		Format: "ok147-target-access-stage-launch-preparation/v1", State: "PREPARED",
		Material: materialReceipt, Candidate: candidateReceipt, MutationAllowed: false,
	}, nil
}

var executeTargetAccessStageLaunch = func(ctx context.Context, config runner.TargetAccessStageLaunchMaterialConfig, authority runner.KubernetesAuthorityConfig, expectedCandidateDigest string) (runner.TargetAccessStageLaunchReceipt, error) {
	material, err := runner.BuildTargetAccessStageLaunchMaterial(config)
	if err != nil {
		return runner.TargetAccessStageLaunchReceipt{}, err
	}
	candidate, err := material.CandidateReceipt()
	if err != nil {
		return runner.TargetAccessStageLaunchReceipt{}, err
	}
	authority.AuthorityIdentity = candidate.Authority
	launcher, err := material.Open(runner.TargetAccessStageLaunchOpenConfig{
		Authority: authority, Clock: func() time.Time { return time.Now().UTC() }, ExpectedCandidateDigest: expectedCandidateDigest,
	})
	if err != nil {
		return runner.TargetAccessStageLaunchReceipt{}, err
	}
	return launcher.Launch(ctx)
}

type targetAccessLaunchPreparation struct {
	Format          string                                         `json:"format"`
	State           string                                         `json:"state"`
	Material        runner.TargetAccessStageLaunchMaterialReceipt  `json:"material"`
	Candidate       runner.TargetAccessStageLaunchCandidateReceipt `json:"candidate"`
	MutationAllowed bool                                           `json:"mutationAllowed"`
}

func targetAccessExpectedObjects(observabilityNamespace, managerServiceAccount, clusterRole, clusterRoleBinding, platformRole, platformRoleBinding, kubeSystemRole, kubeSystemRoleBinding, observerServiceAccount, observerRole, observerRoleBinding string) []projection.ResourceIdentity {
	return []projection.ResourceIdentity{
		{APIVersion: "v1", Kind: "Namespace", Name: observabilityNamespace},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: managerServiceAccount},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: clusterRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: clusterRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: observabilityNamespace, Name: platformRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: observabilityNamespace, Name: platformRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "kube-system", Name: kubeSystemRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "kube-system", Name: kubeSystemRoleBinding},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: observabilityNamespace, Name: observerServiceAccount},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: observabilityNamespace, Name: observerRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: observabilityNamespace, Name: observerRoleBinding},
	}
}

func runClusterStageRunTargetAccessPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run target-access package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifactPath := flags.String("target-access-artifact", "", "path to the exact externally rendered eleven-object target-access set")
	observabilityNamespace := flags.String("observability-namespace", "", "independently expected observability namespace")
	managerServiceAccount := flags.String("manager-serviceaccount", "", "independently expected kube-system manager ServiceAccount")
	clusterRole := flags.String("cluster-role", "", "independently expected cluster role")
	clusterRoleBinding := flags.String("cluster-rolebinding", "", "independently expected cluster role binding")
	platformRole := flags.String("platform-role", "", "independently expected observability namespace role")
	platformRoleBinding := flags.String("platform-rolebinding", "", "independently expected observability namespace role binding")
	kubeSystemRole := flags.String("kube-system-role", "", "independently expected kube-system role")
	kubeSystemRoleBinding := flags.String("kube-system-rolebinding", "", "independently expected kube-system role binding")
	observerServiceAccount := flags.String("observer-serviceaccount", "", "independently expected observability autonomy observer ServiceAccount")
	observerRole := flags.String("observer-role", "", "independently expected observability autonomy observer Role")
	observerRoleBinding := flags.String("observer-rolebinding", "", "independently expected observability autonomy observer RoleBinding")
	jobTemplate := flags.String("job-template", "", "path to the bounded target-access Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	output := flags.String("output", "", "new local file for the verified target-access package")
	runID := flags.String("run-id", "", "bounded OK-147 target-access Job identity")
	imageDigest := flags.String("image", "", "digest-pinned ok image")
	inputConfigMap := flags.String("input-configmap", "", "immutable target-access input ConfigMap name")
	ledgerAPIURL := flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	ledgerAPICIDR := flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	ledgerCredentialSecret := flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	workloadAPIURL := flags.String("workload-api-url", "", "exact workload-writer HTTPS IP endpoint")
	workloadAPICIDR := flags.String("workload-api-cidr", "", "single-address workload-writer CIDR")
	workloadCredentialSecret := flags.String("workload-credential-secret", "", "workload writer credential Secret name")
	workloadBinding := flags.String("workload-binding", "", "path to the private runtime-bound workload authority record")
	workloadBindingDigest := flags.String("workload-binding-digest", "", "expected digest of the private workload authority record")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *grantPath}, {"--grant-key", *grantKeyPath}, {"--evaluation-time", *evaluationTime}, {"--target-access-artifact", *artifactPath},
		{"--observability-namespace", *observabilityNamespace}, {"--manager-serviceaccount", *managerServiceAccount},
		{"--cluster-role", *clusterRole}, {"--cluster-rolebinding", *clusterRoleBinding},
		{"--platform-role", *platformRole}, {"--platform-rolebinding", *platformRoleBinding},
		{"--kube-system-role", *kubeSystemRole}, {"--kube-system-rolebinding", *kubeSystemRoleBinding},
		{"--observer-serviceaccount", *observerServiceAccount}, {"--observer-role", *observerRole}, {"--observer-rolebinding", *observerRoleBinding},
		{"--job-template", *jobTemplate}, {"--job-template-digest", *jobTemplateDigest}, {"--output", *output},
		{"--run-id", *runID}, {"--image", *imageDigest}, {"--input-configmap", *inputConfigMap},
		{"--ledger-api-url", *ledgerAPIURL}, {"--ledger-api-cidr", *ledgerAPICIDR}, {"--ledger-credential-secret", *ledgerCredentialSecret},
		{"--workload-api-url", *workloadAPIURL}, {"--workload-api-cidr", *workloadAPICIDR}, {"--workload-credential-secret", *workloadCredentialSecret},
		{"--workload-binding", *workloadBinding}, {"--workload-binding-digest", *workloadBindingDigest},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	evaluatedAt, err := time.Parse(time.RFC3339, *evaluationTime)
	if err != nil {
		return fmt.Errorf("parse evaluation time: %w", err)
	}
	template, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return fmt.Errorf("read target-access Job template: %w", err)
	}
	expectedObjects := targetAccessExpectedObjects(*observabilityNamespace, *managerServiceAccount, *clusterRole, *clusterRoleBinding, *platformRole, *platformRoleBinding, *kubeSystemRole, *kubeSystemRoleBinding, *observerServiceAccount, *observerRole, *observerRoleBinding)
	raw, receipt, err := materializeTargetAccessStagePackage(runner.TargetAccessStagePackageConfig{
		Bundle: runner.TargetAccessStageBundleConfig{
			PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
			GrantPath: *grantPath, GrantPublicKeyPath: *grantKeyPath, EvaluationTime: evaluatedAt,
			ArtifactPath: *artifactPath, ExpectedObjects: expectedObjects,
		},
		JobTemplate: template, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, InputConfigMap: *inputConfigMap,
		ObservabilityNamespace: *observabilityNamespace, ManagerServiceAccount: *managerServiceAccount,
		ClusterRole: *clusterRole, ClusterRoleBinding: *clusterRoleBinding,
		PlatformRole: *platformRole, PlatformRoleBinding: *platformRoleBinding,
		KubeSystemRole: *kubeSystemRole, KubeSystemRoleBinding: *kubeSystemRoleBinding,
		ObserverServiceAccount: *observerServiceAccount, ObserverRole: *observerRole, ObserverRoleBinding: *observerRoleBinding,
		LedgerAPIURL: *ledgerAPIURL, LedgerAPICIDR: *ledgerAPICIDR, LedgerCredentialSecret: *ledgerCredentialSecret,
		WorkloadAPIURL: *workloadAPIURL, WorkloadAPICIDR: *workloadAPICIDR, WorkloadCredentialSecret: *workloadCredentialSecret,
		WorkloadBindingPath: *workloadBinding, ExpectedWorkloadBindingDigest: *workloadBindingDigest,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return fmt.Errorf("write target-access stage package: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

type targetAccessLaunchMaterialFlags struct {
	resume                                                                                            *stageResumeFlags
	grantPath, grantKeyPath, evaluationTime, artifactPath                                             *string
	observabilityNamespace, managerServiceAccount                                                     *string
	clusterRole, clusterRoleBinding, platformRole, platformRoleBinding                                *string
	kubeSystemRole, kubeSystemRoleBinding                                                             *string
	observerServiceAccount, observerRole, observerRoleBinding                                         *string
	jobTemplate, jobTemplateDigest, runID, imageDigest, inputConfigMap                                *string
	ledgerAPIURL, ledgerAPICIDR, ledgerCredentialSecret                                               *string
	workloadAPIURL, workloadAPICIDR, workloadCredentialSecret, workloadBinding, workloadBindingDigest *string
	materializedAt, runtimeManifest, runtimeManifestDigest                                            *string
	installerAPIEndpoint, installerCADigest, installerTokenDigest, installerEvidence, preparedAt      *string
	ledgerCredential, workloadCredential                                                              *stageLaunchCredentialFlags
}

func addTargetAccessLaunchMaterialFlags(flags *flag.FlagSet) *targetAccessLaunchMaterialFlags {
	values := &targetAccessLaunchMaterialFlags{resume: addStageResumeFlags(flags)}
	values.grantPath = flags.String("grant", "", "path to the signed single-stage grant")
	values.grantKeyPath = flags.String("grant-key", "", "path to the trusted stage-authority public key")
	values.evaluationTime = flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	values.artifactPath = flags.String("target-access-artifact", "", "path to the exact externally rendered eleven-object target-access set")
	values.observabilityNamespace = flags.String("observability-namespace", "", "independently expected observability namespace")
	values.managerServiceAccount = flags.String("manager-serviceaccount", "", "independently expected kube-system manager ServiceAccount")
	values.clusterRole = flags.String("cluster-role", "", "independently expected cluster role")
	values.clusterRoleBinding = flags.String("cluster-rolebinding", "", "independently expected cluster role binding")
	values.platformRole = flags.String("platform-role", "", "independently expected observability namespace role")
	values.platformRoleBinding = flags.String("platform-rolebinding", "", "independently expected observability namespace role binding")
	values.kubeSystemRole = flags.String("kube-system-role", "", "independently expected kube-system role")
	values.kubeSystemRoleBinding = flags.String("kube-system-rolebinding", "", "independently expected kube-system role binding")
	values.observerServiceAccount = flags.String("observer-serviceaccount", "", "independently expected observability autonomy observer ServiceAccount")
	values.observerRole = flags.String("observer-role", "", "independently expected observability autonomy observer Role")
	values.observerRoleBinding = flags.String("observer-rolebinding", "", "independently expected observability autonomy observer RoleBinding")
	values.jobTemplate = flags.String("job-template", "", "path to the bounded target-access Job template")
	values.jobTemplateDigest = flags.String("job-template-digest", "", "expected SHA-256 identity of the Job template")
	values.runID = flags.String("run-id", "", "bounded OK-147 target-access Job identity")
	values.imageDigest = flags.String("image", "", "digest-pinned ok image")
	values.inputConfigMap = flags.String("input-configmap", "", "immutable target-access input ConfigMap name")
	values.ledgerAPIURL = flags.String("ledger-api-url", "", "exact management-ledger HTTPS IP endpoint")
	values.ledgerAPICIDR = flags.String("ledger-api-cidr", "", "single-address management-ledger CIDR")
	values.ledgerCredentialSecret = flags.String("ledger-credential-secret", "", "ledger credential Secret name")
	values.workloadAPIURL = flags.String("workload-api-url", "", "exact workload-writer HTTPS IP endpoint")
	values.workloadAPICIDR = flags.String("workload-api-cidr", "", "single-address workload-writer CIDR")
	values.workloadCredentialSecret = flags.String("workload-credential-secret", "", "workload writer credential Secret name")
	values.workloadBinding = flags.String("workload-binding", "", "path to the private runtime-bound workload authority record")
	values.workloadBindingDigest = flags.String("workload-binding-digest", "", "expected digest of the private workload authority record")
	values.materializedAt = flags.String("credential-materialized-at", "", "exact credential materialization time")
	values.ledgerCredential = addStageLaunchCredentialFlags(flags, "ledger-job", "ledger Job credential")
	values.workloadCredential = addStageLaunchCredentialFlags(flags, "workload-writer-job", "workload writer Job credential")
	values.runtimeManifest = flags.String("runtime-manifest", "", "path to the tokenless runtime ServiceAccount manifest")
	values.runtimeManifestDigest = flags.String("runtime-manifest-digest", "", "expected runtime manifest digest")
	values.installerAPIEndpoint = flags.String("installer-api-endpoint", "", "exact execution-plane installer HTTPS IP endpoint")
	values.installerCADigest = flags.String("installer-ca-digest", "", "expected execution-plane installer CA digest")
	values.installerTokenDigest = flags.String("installer-token-digest", "", "private expected execution-plane installer token digest")
	values.installerEvidence = flags.String("installer-tokenrequest-evidence-digest", "", "execution-plane installer TokenRequest evidence digest")
	values.preparedAt = flags.String("prepared-at", "", "exact launch candidate preparation time")
	return values
}

func (values *targetAccessLaunchMaterialFlags) config() (runner.TargetAccessStageLaunchMaterialConfig, error) {
	resume, err := values.resume.config()
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, err
	}
	for _, input := range []struct{ name, value string }{
		{"--grant", *values.grantPath}, {"--grant-key", *values.grantKeyPath}, {"--evaluation-time", *values.evaluationTime}, {"--target-access-artifact", *values.artifactPath},
		{"--observability-namespace", *values.observabilityNamespace}, {"--manager-serviceaccount", *values.managerServiceAccount},
		{"--cluster-role", *values.clusterRole}, {"--cluster-rolebinding", *values.clusterRoleBinding},
		{"--platform-role", *values.platformRole}, {"--platform-rolebinding", *values.platformRoleBinding},
		{"--kube-system-role", *values.kubeSystemRole}, {"--kube-system-rolebinding", *values.kubeSystemRoleBinding},
		{"--observer-serviceaccount", *values.observerServiceAccount}, {"--observer-role", *values.observerRole}, {"--observer-rolebinding", *values.observerRoleBinding},
		{"--job-template", *values.jobTemplate}, {"--job-template-digest", *values.jobTemplateDigest}, {"--run-id", *values.runID}, {"--image", *values.imageDigest},
		{"--input-configmap", *values.inputConfigMap}, {"--ledger-api-url", *values.ledgerAPIURL}, {"--ledger-api-cidr", *values.ledgerAPICIDR},
		{"--ledger-credential-secret", *values.ledgerCredentialSecret}, {"--workload-api-url", *values.workloadAPIURL},
		{"--workload-api-cidr", *values.workloadAPICIDR}, {"--workload-credential-secret", *values.workloadCredentialSecret},
		{"--workload-binding", *values.workloadBinding}, {"--workload-binding-digest", *values.workloadBindingDigest},
		{"--credential-materialized-at", *values.materializedAt}, {"--runtime-manifest", *values.runtimeManifest},
		{"--runtime-manifest-digest", *values.runtimeManifestDigest}, {"--installer-api-endpoint", *values.installerAPIEndpoint},
		{"--installer-ca-digest", *values.installerCADigest}, {"--installer-token-digest", *values.installerTokenDigest},
		{"--installer-tokenrequest-evidence-digest", *values.installerEvidence}, {"--prepared-at", *values.preparedAt},
	} {
		if input.value == "" {
			return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("%s is required", input.name)
		}
	}
	evaluatedAt, err := time.Parse(time.RFC3339, *values.evaluationTime)
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("parse evaluation time: %w", err)
	}
	materializedAt, err := time.Parse(time.RFC3339, *values.materializedAt)
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("parse credential materialization time: %w", err)
	}
	preparedAt, err := time.Parse(time.RFC3339, *values.preparedAt)
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("parse candidate preparation time: %w", err)
	}
	ledgerSource, err := values.ledgerCredential.source("ledger-job")
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, err
	}
	workloadSource, err := values.workloadCredential.source("workload-writer-job")
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, err
	}
	template, err := readBoundedLocalFile(*values.jobTemplate, 1024*1024)
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("read target-access Job template: %w", err)
	}
	runtimeRaw, err := readBoundedLocalFile(*values.runtimeManifest, 128*1024)
	if err != nil {
		return runner.TargetAccessStageLaunchMaterialConfig{}, fmt.Errorf("read runtime manifest: %w", err)
	}
	expectedObjects := targetAccessExpectedObjects(*values.observabilityNamespace, *values.managerServiceAccount, *values.clusterRole, *values.clusterRoleBinding, *values.platformRole, *values.platformRoleBinding, *values.kubeSystemRole, *values.kubeSystemRoleBinding, *values.observerServiceAccount, *values.observerRole, *values.observerRoleBinding)
	return runner.TargetAccessStageLaunchMaterialConfig{
		Package: runner.TargetAccessStagePackageConfig{
			Bundle: runner.TargetAccessStageBundleConfig{
				PlanPath: resume.PlanPath, PlanExpected: resume.PlanExpected, Receipts: resume.Receipts,
				GrantPath: *values.grantPath, GrantPublicKeyPath: *values.grantKeyPath, EvaluationTime: evaluatedAt,
				ArtifactPath: *values.artifactPath, ExpectedObjects: expectedObjects,
			},
			JobTemplate: template, JobTemplateDigest: *values.jobTemplateDigest,
			RunID: *values.runID, ImageDigest: *values.imageDigest, InputConfigMap: *values.inputConfigMap,
			ObservabilityNamespace: *values.observabilityNamespace, ManagerServiceAccount: *values.managerServiceAccount,
			ClusterRole: *values.clusterRole, ClusterRoleBinding: *values.clusterRoleBinding,
			PlatformRole: *values.platformRole, PlatformRoleBinding: *values.platformRoleBinding,
			KubeSystemRole: *values.kubeSystemRole, KubeSystemRoleBinding: *values.kubeSystemRoleBinding,
			ObserverServiceAccount: *values.observerServiceAccount, ObserverRole: *values.observerRole, ObserverRoleBinding: *values.observerRoleBinding,
			LedgerAPIURL: *values.ledgerAPIURL, LedgerAPICIDR: *values.ledgerAPICIDR, LedgerCredentialSecret: *values.ledgerCredentialSecret,
			WorkloadAPIURL: *values.workloadAPIURL, WorkloadAPICIDR: *values.workloadAPICIDR, WorkloadCredentialSecret: *values.workloadCredentialSecret,
			WorkloadBindingPath: *values.workloadBinding, ExpectedWorkloadBindingDigest: *values.workloadBindingDigest,
		},
		MaterializationTime: materializedAt, LedgerWriter: ledgerSource, WorkloadWriter: workloadSource,
		RuntimeManifest: runtimeRaw, RuntimeManifestDigest: *values.runtimeManifestDigest,
		Candidate: runner.SubmissionStageLaunchCandidateConfig{
			AuthorityEndpoint: *values.installerAPIEndpoint, CABundleDigest: *values.installerCADigest,
			InstallerTokenDigest: *values.installerTokenDigest, InstallerCredentialEvidenceDigest: *values.installerEvidence,
			PreparedAt: preparedAt,
		},
	}, nil
}

func runClusterStageRunTargetAccessLaunchPrepare(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run target-access launch prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addTargetAccessLaunchMaterialFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	preparation, err := prepareTargetAccessStageLaunch(config)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(preparation)
}

func runClusterStageRunTargetAccessLaunchExecute(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run target-access launch execute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	materialFlags := addTargetAccessLaunchMaterialFlags(flags)
	execute := flags.Bool("execute", false, "perform the exact single-use six-object Target Access launch")
	expectedCandidateDigest := flags.String("expected-candidate-digest", "", "exact digest emitted by Target Access launch prepare")
	installerTokenFile := flags.String("installer-token-file", "", "bounded short-lived execution-plane installer token file")
	installerCAFile := flags.String("installer-ca-file", "", "bounded execution-plane installer CA file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*execute {
		return errors.New("target-access launch mutation requires explicit --execute")
	}
	for _, input := range []struct{ name, value string }{
		{"--expected-candidate-digest", *expectedCandidateDigest}, {"--installer-token-file", *installerTokenFile}, {"--installer-ca-file", *installerCAFile},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	if !sha256DigestPattern.MatchString(*expectedCandidateDigest) {
		return errors.New("--expected-candidate-digest must be sha256:<64 lowercase hex>")
	}
	config, err := materialFlags.config()
	if err != nil {
		return err
	}
	boundedContext, cancel := context.WithTimeout(ctx, stageLaunchTimeout)
	defer cancel()
	receipt, launchErr := executeTargetAccessStageLaunch(boundedContext, config, runner.KubernetesAuthorityConfig{
		Endpoint: config.Candidate.AuthorityEndpoint, TokenFile: *installerTokenFile,
		CAFile: *installerCAFile, CABundleDigest: config.Candidate.CABundleDigest,
	}, *expectedCandidateDigest)
	if receipt.Format != "" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
	}
	return launchErr
}
