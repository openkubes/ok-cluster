package stageplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
)

func TestVerifyAcceptsExactBoundedSequence(t *testing.T) {
	raw := planJSON(t, validDocument())
	binding, err := Verify(raw, expected())
	if err != nil {
		t.Fatal(err)
	}
	if binding.Format != BindingFormat || binding.PlanDigest == "" || len(binding.Stages) != 12 {
		t.Fatalf("unexpected binding: %#v", binding)
	}
	if !IsMutating(binding.Stages[0]) || IsMutating(binding.Stages[2]) {
		t.Fatal("mutation classification differs from grant operations")
	}
	if names := InputNames(binding.Stages[0]); len(names) != 1 || names[0] != "projection.provider-prerequisites" {
		t.Fatalf("unexpected redacted input names: %v", names)
	}
}

func TestVerifyRejectsSequenceAuthorityAndGrantChanges(t *testing.T) {
	tests := map[string]func(*document){
		"missing stage":       func(plan *document) { plan.Stages = plan.Stages[:11] },
		"reordered stage":     func(plan *document) { plan.Stages[0], plan.Stages[1] = plan.Stages[1], plan.Stages[0] },
		"wrong dependency":    func(plan *document) { plan.Stages[4].Requires = []string{"cluster-lifecycle"} },
		"authority drift":     func(plan *document) { plan.Stages[3].Authority = "runner" },
		"grant removed":       func(plan *document) { plan.Stages[3].GrantOperation = "" },
		"grant added to read": func(plan *document) { plan.Stages[4].GrantOperation = "ObserveNetwork" },
		"missing input":       func(plan *document) { plan.Stages[9].Inputs = nil },
		"duplicate input":     func(plan *document) { plan.Stages[9].Inputs = append(plan.Stages[9].Inputs, plan.Stages[9].Inputs[0]) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validDocument()
			mutate(&plan)
			if _, err := Verify(planJSON(t, plan), expected()); err == nil {
				t.Fatal("changed staged plan was accepted")
			}
		})
	}
}

func TestVerifyRejectsAuthorizationAndRevisionDrift(t *testing.T) {
	tests := map[string]func(*document){
		"authorizing document":   func(plan *document) { plan.AuthorizationState = "GO" },
		"wrong identity":         func(plan *document) { plan.ContractIdentity.Name = "another-cluster" },
		"wrong R":                func(plan *document) { plan.IntentRevision = sha("9") },
		"wrong E":                func(plan *document) { plan.EnablementRevision = sha("8") },
		"wrong P":                func(plan *document) { plan.PlatformRevision = sha("7") },
		"wrong fixture":          func(plan *document) { plan.ExecutionFixture = sha("6") },
		"wrong GitOps authority": func(plan *document) { plan.Authorities.GitOps = "other-shared" },
		"wrong workload mode":    func(plan *document) { plan.Authorities.WorkloadIdentityMode = "endpoint-name/v1" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := validDocument()
			mutate(&plan)
			if _, err := Verify(planJSON(t, plan), expected()); err == nil {
				t.Fatal("foreign execution identity was accepted")
			}
		})
	}
}

func TestVerifyIsCanonicalAndStrict(t *testing.T) {
	first := planJSON(t, validDocument())
	var generic map[string]any
	if err := json.Unmarshal(first, &generic); err != nil {
		t.Fatal(err)
	}
	second, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	one, err := Verify(first, expected())
	if err != nil {
		t.Fatal(err)
	}
	two, err := Verify(second, expected())
	if err != nil || one.PlanDigest != two.PlanDigest {
		t.Fatalf("canonical plan identity differs: %s %s %v", one.PlanDigest, two.PlanDigest, err)
	}
	duplicate := strings.Replace(string(first), `"format":"`+Format+`"`, `"format":"`+Format+`","format":"`+Format+`"`, 1)
	if _, err := Verify([]byte(duplicate), expected()); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	unknown := strings.Replace(string(first), `"format":"`+Format+`"`, `"format":"`+Format+`","unknown":true`, 1)
	if _, err := Verify([]byte(unknown), expected()); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "plan.json")
	if err := os.WriteFile(actual, planJSON(t, validDocument()), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "plan-link.json")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link, expected()); err == nil {
		t.Fatal("symlinked plan was accepted")
	}
}

func validDocument() document {
	stages := make([]Stage, 0, len(requiredSequence))
	for index, rule := range requiredSequence {
		stages = append(stages, Stage{
			ID: rule.id, Order: index + 1, Kind: rule.kind, Authority: rule.authority,
			GrantOperation: rule.grantOperation, Requires: append([]string(nil), rule.requires...),
			Inputs: []Input{{Name: inputName(rule.id), Digest: sha(string("abcdef012345"[index]))}},
		})
	}
	return document{
		Format: Format, ContractIdentity: contractIdentity(), IntentRevision: sha("1"), EnablementRevision: sha("2"),
		PlatformRevision: sha("3"), ExecutionFixture: sha("4"), AuthorizationState: "NO-GO",
		Authorities: Authorities{Infrastructure: "ok-infra", Management: "ok-mgmt", GitOps: "ok-shared", WorkloadIdentityMode: "capi-cluster-uid/v1", RunnerIdentityMode: "bounded-job/v1"},
		Stages:      stages,
	}
}

func expected() Expected {
	return Expected{ContractIdentity: contractIdentity(), IntentRevision: sha("1"), EnablementRevision: sha("2"), PlatformRevision: sha("3"), ExecutionFixture: sha("4"), InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-shared"}
}

func contractIdentity() contract.Identity {
	return contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
}

func inputName(stage string) string {
	if stage == "provider-prerequisites" {
		return "projection.provider-prerequisites"
	}
	return "stage." + stage
}

func planJSON(t *testing.T, value document) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sha(value string) string { return "sha256:" + strings.Repeat(value, 64) }
