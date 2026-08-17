package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
)

func targetAccessExpectedObjects(observabilityNamespace, managerServiceAccount, clusterRole, clusterRoleBinding, platformRole, platformRoleBinding, kubeSystemRole, kubeSystemRoleBinding string) []projection.ResourceIdentity {
	return []projection.ResourceIdentity{
		{APIVersion: "v1", Kind: "Namespace", Name: observabilityNamespace},
		{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: managerServiceAccount},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: clusterRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: clusterRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: observabilityNamespace, Name: platformRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: observabilityNamespace, Name: platformRoleBinding},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "kube-system", Name: kubeSystemRole},
		{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "kube-system", Name: kubeSystemRoleBinding},
	}
}

func runClusterStageRunTargetAccessPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage run target-access package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	grantPath := flags.String("grant", "", "path to the signed single-stage grant")
	grantKeyPath := flags.String("grant-key", "", "path to the trusted stage-authority public key")
	evaluationTime := flags.String("evaluation-time", "", "explicit RFC3339 grant evaluation time")
	artifactPath := flags.String("target-access-artifact", "", "path to the exact externally rendered eight-object target-access set")
	observabilityNamespace := flags.String("observability-namespace", "", "independently expected observability namespace")
	managerServiceAccount := flags.String("manager-serviceaccount", "", "independently expected kube-system manager ServiceAccount")
	clusterRole := flags.String("cluster-role", "", "independently expected cluster role")
	clusterRoleBinding := flags.String("cluster-rolebinding", "", "independently expected cluster role binding")
	platformRole := flags.String("platform-role", "", "independently expected observability namespace role")
	platformRoleBinding := flags.String("platform-rolebinding", "", "independently expected observability namespace role binding")
	kubeSystemRole := flags.String("kube-system-role", "", "independently expected kube-system role")
	kubeSystemRoleBinding := flags.String("kube-system-rolebinding", "", "independently expected kube-system role binding")
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
	expectedObjects := targetAccessExpectedObjects(*observabilityNamespace, *managerServiceAccount, *clusterRole, *clusterRoleBinding, *platformRole, *platformRoleBinding, *kubeSystemRole, *kubeSystemRoleBinding)
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
