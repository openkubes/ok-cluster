package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestRenderTargetAccessStageJobBindsExactEnvelope(t *testing.T) {
	values := validTargetAccessStageJobValues()
	raw, err := RenderTargetAccessStageJobTemplate(targetAccessStageJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("${"), []byte("system:masters"), []byte("privileged: true"), []byte("kubernetes.default.svc")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("materialized target-access Job contains forbidden boundary %q", forbidden)
		}
	}
	objects := decodeJobObjects(t, raw)
	job, policy := objects["Job"], objects["NetworkPolicy"]
	if len(objects) != 2 || job == nil || policy == nil {
		t.Fatalf("unexpected target-access envelope: %#v", objects)
	}
	jobSpec := objectAt(t, job, "spec")
	if jobSpec["backoffLimit"] != 0 || jobSpec["parallelism"] != 1 || jobSpec["completions"] != 1 || jobSpec["activeDeadlineSeconds"] != 300 {
		t.Fatalf("target-access Job boundary differs: %#v", jobSpec)
	}
	podSpec := objectAt(t, objectAt(t, jobSpec, "template"), "spec")
	if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
		t.Fatalf("unexpected target-access Pod identity: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	for _, required := range []string{
		"cluster", "stage", "run", "target-access", "--execute", "--grant",
		"--target-access-artifact", "--ledger-token-file", "--workload-binding",
		"--workload-binding-digest", "--workload-token-file",
	} {
		if !contains(args, required) {
			t.Fatalf("target-access Job args do not bind %s: %v", required, args)
		}
	}
	for argument, want := range map[string]string{
		"--observability-namespace": values.ObservabilityNamespace,
		"--manager-serviceaccount":  values.ManagerServiceAccount,
		"--cluster-role":            values.ClusterRole,
		"--cluster-rolebinding":     values.ClusterRoleBinding,
		"--platform-role":           values.PlatformRole,
		"--platform-rolebinding":    values.PlatformRoleBinding,
		"--kube-system-role":        values.KubeSystemRole,
		"--kube-system-rolebinding": values.KubeSystemRoleBinding,
		"--observer-serviceaccount": values.ObserverServiceAccount,
		"--observer-role":           values.ObserverRole,
		"--observer-rolebinding":    values.ObserverRoleBinding,
	} {
		if got := argumentValue(args, argument); got != want {
			t.Fatalf("target-access Job %s=%q, want %q", argument, got, want)
		}
	}
	receiptCount := 0
	for _, argument := range args {
		if argument == "--receipt" {
			receiptCount++
		}
	}
	if receiptCount != 6 {
		t.Fatalf("receipt arguments=%d, want 6", receiptCount)
	}
	if mounts := arrayAt(t, container, "volumeMounts"); len(mounts) != 16 {
		t.Fatalf("target-access volumeMounts=%d, want 16", len(mounts))
	}
	policySpec := objectAt(t, policy, "spec")
	if len(arrayAt(t, policySpec, "ingress")) != 0 || len(arrayAt(t, policySpec, "egress")) != 2 {
		t.Fatalf("target-access NetworkPolicy is not two-endpoint deny-all: %#v", policySpec)
	}
}

func TestRenderTargetAccessStageJobFailsClosed(t *testing.T) {
	template := targetAccessStageJobTemplate(t)
	for name, mutate := range map[string]func(*TargetAccessStageJobValues){
		"mutable image": func(values *TargetAccessStageJobValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"shared credential": func(values *TargetAccessStageJobValues) {
			values.WorkloadCredentialSecret = values.LedgerCredentialSecret
		},
		"shared endpoint": func(values *TargetAccessStageJobValues) {
			values.WorkloadAPIURL = values.LedgerAPIURL
			values.WorkloadAPICIDR = values.LedgerAPICIDR
		},
		"broad workload CIDR": func(values *TargetAccessStageJobValues) { values.WorkloadAPICIDR = "192.0.2.0/24" },
		"DNS endpoint": func(values *TargetAccessStageJobValues) {
			values.WorkloadAPIURL = "https://kubernetes.default.svc:6443"
		},
		"invalid object name":    func(values *TargetAccessStageJobValues) { values.PlatformRole = "Bad_Name" },
		"foreign binding digest": func(values *TargetAccessStageJobValues) { values.WorkloadBindingDigest = "sha256:short" },
		"foreign authority": func(values *TargetAccessStageJobValues) {
			values.Expected.GitOpsAuthority = values.Expected.ManagementAuthority
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := validTargetAccessStageJobValues()
			mutate(&values)
			if _, err := RenderTargetAccessStageJobTemplate(template, values); err == nil {
				t.Fatal("unsafe target-access stage Job was accepted")
			}
		})
	}
	if _, err := RenderTargetAccessStageJobTemplate(append(template, []byte("\n${UNKNOWN}")...), validTargetAccessStageJobValues()); err == nil {
		t.Fatal("unknown target-access placeholder was accepted")
	}
}

func validTargetAccessStageJobValues() TargetAccessStageJobValues {
	return TargetAccessStageJobValues{
		RunID: "ok147-target-access-20260817-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@sha256:" + strings.Repeat("a", 64),
		EvaluationTime: "2026-08-17T14:00:00Z",
		Expected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
			IntentRevision:   prefixSHA("a"), EnablementRevision: prefixSHA("b"), PlatformRevision: prefixSHA("c"), ExecutionFixture: prefixSHA("d"),
			InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
		},
		InputConfigMap: "ok147-target-access-input", ReceiptPrefixDigest: prefixSHA("e"),
		ObservabilityNamespace: "ok-observability", ManagerServiceAccount: "ok147-argocd-manager",
		ClusterRole: "ok147-argocd-platform-cluster", ClusterRoleBinding: "ok147-argocd-platform-cluster",
		PlatformRole: "ok147-argocd-platform", PlatformRoleBinding: "ok147-argocd-platform",
		KubeSystemRole: "ok147-argocd-kube-system", KubeSystemRoleBinding: "ok147-argocd-kube-system",
		ObserverServiceAccount: "ok147-observability-autonomy", ObserverRole: "ok147-observability-autonomy", ObserverRoleBinding: "ok147-observability-autonomy",
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-credential",
		WorkloadAPIURL: "https://192.0.2.13:6443", WorkloadAPICIDR: "192.0.2.13/32", WorkloadCredentialSecret: "ok147-workload-credential",
		WorkloadBindingDigest: prefixSHA("f"),
	}
}

func targetAccessStageJobTemplate(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-target-access-job.yaml.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
