package runner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"gopkg.in/yaml.v3"
)

func TestSubmissionStageJobIsBoundedToStageCredentialsAndEndpoints(t *testing.T) {
	raw := submissionStageJobTemplate(t)
	for _, stageID := range []string{"provider-prerequisites", "cluster-lifecycle"} {
		t.Run(stageID, func(t *testing.T) {
			values := validSubmissionStageJobValues()
			values.StageID = stageID
			if stageID == "cluster-lifecycle" {
				values.AuthorityAPIURL, values.AuthorityAPICIDR = values.LedgerAPIURL, values.LedgerAPICIDR
				values.InputDataKeys = append(values.InputDataKeys, providerReceiptInputKey)
			}
			materialized, err := RenderSubmissionStageJobTemplate(raw, values)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(materialized, []byte("${")) || bytes.Contains(materialized, []byte("system:masters")) || bytes.Contains(materialized, []byte("privileged: true")) {
				t.Fatal("materialized Job contains an unresolved or privileged boundary")
			}
			objects := decodeJobObjects(t, materialized)
			job, policy := objects["Job"], objects["NetworkPolicy"]
			if job == nil || policy == nil {
				t.Fatal("submission template must contain one Job and NetworkPolicy")
			}
			jobSpec := objectAt(t, job, "spec")
			if jobSpec["backoffLimit"] != 0 || jobSpec["parallelism"] != 1 || jobSpec["completions"] != 1 {
				t.Fatalf("Job retry/singleton boundary differs: %#v", jobSpec)
			}
			podSpec := objectAt(t, objectAt(t, jobSpec, "template"), "spec")
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false || podSpec["restartPolicy"] != "Never" {
				t.Fatalf("unexpected Pod identity: %#v", podSpec)
			}
			containers := arrayAt(t, podSpec, "containers")
			if len(containers) != 1 {
				t.Fatalf("containers=%d, want 1", len(containers))
			}
			container := containers[0].(map[string]any)
			args := stringArray(t, container, "args")
			for _, required := range []string{"cluster", "stage", "run", "--execute", "--expected-stage", "--receipt-prefix", "--receipt-prefix-digest", "--ledger-token-file", "--authority-token-file"} {
				if !contains(args, required) {
					t.Fatalf("Job args do not bind %s: %v", required, args)
				}
			}
			for _, forbidden := range []string{"shell", "apply", "delete", "--command", "--receipt"} {
				if contains(args, forbidden) {
					t.Fatalf("Job args contain forbidden operation %s", forbidden)
				}
			}
			mounts := arrayAt(t, container, "volumeMounts")
			wantMounts := len(values.InputDataKeys) + 4
			if len(mounts) != wantMounts {
				t.Fatalf("volumeMounts=%d, want %d", len(mounts), wantMounts)
			}
			inputMounts := 0
			for _, rawMount := range mounts {
				mount := rawMount.(map[string]any)
				if mount["readOnly"] != true {
					t.Fatalf("input/credential is not read-only: %#v", mount)
				}
				if mount["name"] == "input" {
					key, ok := mount["subPath"].(string)
					if !ok || mount["mountPath"] != "/var/run/openkubes/input/"+key || !contains(values.InputDataKeys, key) {
						t.Fatalf("verified input is not an exact subPath mount: %#v", mount)
					}
					inputMounts++
				} else if mount["subPath"] == nil {
					t.Fatalf("credential is not a bounded subPath mount: %#v", mount)
				}
			}
			if inputMounts != len(values.InputDataKeys) {
				t.Fatalf("input mounts=%d, want %d for %s", inputMounts, len(values.InputDataKeys), stageID)
			}
			policySpec := objectAt(t, policy, "spec")
			if ingress := arrayAt(t, policySpec, "ingress"); len(ingress) != 0 {
				t.Fatal("NetworkPolicy ingress is not deny-all")
			}
			if egress := arrayAt(t, policySpec, "egress"); len(egress) != 2 {
				t.Fatalf("NetworkPolicy egress=%d, want 2", len(egress))
			}
		})
	}
}

func TestRenderSubmissionStageJobFailsClosed(t *testing.T) {
	template := submissionStageJobTemplate(t)
	for name, mutate := range map[string]func(*SubmissionStageJobValues){
		"unsupported stage": func(values *SubmissionStageJobValues) { values.StageID = "enablement" },
		"shared credential": func(values *SubmissionStageJobValues) {
			values.AuthorityCredentialSecret = values.LedgerCredentialSecret
		},
		"mutable image": func(values *SubmissionStageJobValues) { values.ImageDigest = "ghcr.io/openkubes/ok-cluster:latest" },
		"DNS endpoint":  func(values *SubmissionStageJobValues) { values.AuthorityAPIURL = "https://kubernetes.default.svc:6443" },
		"broad CIDR":    func(values *SubmissionStageJobValues) { values.AuthorityAPICIDR = "192.0.2.0/24" },
		"missing port":  func(values *SubmissionStageJobValues) { values.AuthorityAPIURL = "https://192.0.2.11" },
		"foreign authority": func(values *SubmissionStageJobValues) {
			values.Expected.ManagementAuthority = values.Expected.InfrastructureAuthority
		},
		"provider on ledger": func(values *SubmissionStageJobValues) {
			values.AuthorityAPIURL, values.AuthorityAPICIDR = values.LedgerAPIURL, values.LedgerAPICIDR
		},
		"cluster outside ledger": func(values *SubmissionStageJobValues) { values.StageID = "cluster-lifecycle" },
	} {
		t.Run(name, func(t *testing.T) {
			values := validSubmissionStageJobValues()
			mutate(&values)
			if _, err := RenderSubmissionStageJobTemplate(template, values); err == nil {
				t.Fatal("unsafe submission stage Job was accepted")
			}
		})
	}
	if _, err := RenderSubmissionStageJobTemplate(append(template, []byte("\n${UNKNOWN}")...), validSubmissionStageJobValues()); err == nil {
		t.Fatal("unknown placeholder was accepted")
	}
}

func validSubmissionStageJobValues() SubmissionStageJobValues {
	return SubmissionStageJobValues{
		RunID: "ok147-provider-20260816-01", StageID: "provider-prerequisites",
		ImageDigest: "ghcr.io/openkubes/ok-cluster@sha256:" + strings.Repeat("a", 64), EvaluationTime: "2026-08-16T15:00:00Z",
		Expected: stageplan.Expected{
			ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
			IntentRevision:   prefixSHA("a"), EnablementRevision: prefixSHA("b"), PlatformRevision: prefixSHA("c"), ExecutionFixture: prefixSHA("d"),
			InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared",
		},
		InputConfigMap: "ok147-provider-input", ReceiptPrefixDigest: prefixSHA("e"),
		LedgerAPIURL: "https://192.0.2.12:6443", LedgerAPICIDR: "192.0.2.12/32", LedgerCredentialSecret: "ok147-ledger-credential",
		AuthorityAPIURL: "https://192.0.2.11:6443", AuthorityAPICIDR: "192.0.2.11/32", AuthorityCredentialSecret: "ok147-authority-credential",
		InputDataKeys: []string{
			"authority-map.json", "ok-infra-prerequisites.yaml", "ok-mgmt-lifecycle.yaml", "projection-manifest.json",
			"receipt-prefix.json", "renderer-input.yaml", "renderer-source.yaml", "resolved-renderer-input.yaml",
			"stage-authority.pub", "stage-grant.json", "staged-plan.json",
		},
	}
}

func submissionStageJobTemplate(t *testing.T) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-stage-job.yaml.tpl"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeJobObjects(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := map[string]map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				return objects
			}
			t.Fatal(err)
		}
		kind, _ := object["kind"].(string)
		objects[kind] = object
	}
}
