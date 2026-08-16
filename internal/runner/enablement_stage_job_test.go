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

func TestRenderEnablementStageJobBindsExactEnvelope(t *testing.T) {
	values := validEnablementStageJobValues()
	raw, err := RenderEnablementStageJobTemplate(enablementStageJobTemplate(t), values)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("${")) || bytes.Contains(raw, []byte("system:masters")) || bytes.Contains(raw, []byte("privileged: true")) {
		t.Fatal("materialized enablement Job contains an unresolved or privileged boundary")
	}
	objects := decodeJobObjects(t, raw)
	job, policy := objects["Job"], objects["NetworkPolicy"]
	if len(objects) != 2 || job == nil || policy == nil {
		t.Fatalf("unexpected enablement envelope: %#v", objects)
	}
	jobSpec := objectAt(t, job, "spec")
	if jobSpec["backoffLimit"] != 0 || jobSpec["parallelism"] != 1 || jobSpec["completions"] != 1 || jobSpec["activeDeadlineSeconds"] != 660 {
		t.Fatalf("enablement Job boundary differs: %#v", jobSpec)
	}
	podSpec := objectAt(t, objectAt(t, jobSpec, "template"), "spec")
	if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
		t.Fatalf("unexpected enablement Pod identity: %#v", podSpec)
	}
	container := arrayAt(t, podSpec, "containers")[0].(map[string]any)
	args := stringArray(t, container, "args")
	for _, required := range []string{"cluster", "stage", "run", "enablement", "--execute", "--grant", "--enablement-artifact", "--helmchartproxy-name", "--ledger-token-file", "--management-token-file"} {
		if !contains(args, required) {
			t.Fatalf("enablement Job args do not bind %s: %v", required, args)
		}
	}
	if argumentValue(args, "--helmchartproxy-name") != values.HelmChartProxyName {
		t.Fatal("enablement Job does not bind independently expected HCP name")
	}
	receiptCount := 0
	for _, argument := range args {
		if argument == "--receipt" {
			receiptCount++
		}
	}
	if receiptCount != 3 {
		t.Fatalf("receipt arguments=%d, want 3", receiptCount)
	}
	if mounts := arrayAt(t, container, "volumeMounts"); len(mounts) != 12 {
		t.Fatalf("enablement volumeMounts=%d, want 12", len(mounts))
	}
	policySpec := objectAt(t, policy, "spec")
	if len(arrayAt(t, policySpec, "ingress")) != 0 || len(arrayAt(t, policySpec, "egress")) != 1 {
		t.Fatalf("enablement NetworkPolicy is not single-endpoint deny-all: %#v", policySpec)
	}
}

func TestRenderEnablementStageJobFailsClosed(t *testing.T) {
	template := enablementStageJobTemplate(t)
	for name, mutate := range map[string]func(*EnablementStageJobValues){
		"mutable image": func(values *EnablementStageJobValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"shared credential": func(values *EnablementStageJobValues) {
			values.ManagementCredentialSecret = values.LedgerCredentialSecret
		},
		"foreign management endpoint": func(values *EnablementStageJobValues) { values.ManagementAPIURL = "https://192.0.2.13:6443" },
		"broad management CIDR":       func(values *EnablementStageJobValues) { values.ManagementAPICIDR = "192.0.2.0/24" },
		"DNS endpoint": func(values *EnablementStageJobValues) {
			values.ManagementAPIURL = "https://kubernetes.default.svc:6443"
		},
		"invalid HCP name": func(values *EnablementStageJobValues) { values.HelmChartProxyName = "Bad_Name" },
		"foreign authority": func(values *EnablementStageJobValues) {
			values.Expected.ManagementAuthority = values.Expected.InfrastructureAuthority
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := validEnablementStageJobValues()
			mutate(&values)
			if _, err := RenderEnablementStageJobTemplate(template, values); err == nil {
				t.Fatal("unsafe enablement stage Job was accepted")
			}
		})
	}
	if _, err := RenderEnablementStageJobTemplate(append(template, []byte("\n${UNKNOWN}")...), validEnablementStageJobValues()); err == nil {
		t.Fatal("unknown enablement placeholder was accepted")
	}
}

func validEnablementStageJobValues() EnablementStageJobValues {
	return EnablementStageJobValues{
		RunID: "ok147-enablement-20260816-01", ImageDigest: "ghcr.io/openkubes/ok-cluster@sha256:" + strings.Repeat("a", 64),
		EvaluationTime: "2026-08-16T21:00:00Z",
		Expected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
			IntentRevision:   prefixSHA("a"), EnablementRevision: prefixSHA("b"), PlatformRevision: prefixSHA("c"), ExecutionFixture: prefixSHA("d"),
			InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
		},
		InputConfigMap: "ok147-enablement-input", ReceiptPrefixDigest: prefixSHA("e"), HelmChartProxyName: "disposable-ok147-cilium",
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-credential",
		ManagementAPIURL: "https://192.0.2.12:6443", ManagementAPICIDR: "192.0.2.12/32", ManagementCredentialSecret: "ok147-management-credential",
	}
}

func enablementStageJobTemplate(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-enablement-job.yaml.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
