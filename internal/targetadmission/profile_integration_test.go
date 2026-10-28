package targetadmission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/runnerprofile"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestVerifiedMVPProfileTargetAccessCompilesIntoExactAdmissionPolicy(t *testing.T) {
	const (
		enablement = "sha256:2a849d69e9c64344e907c1bce3bb1abf3d8f77217377081a5be055d62c213300"
		platform   = "sha256:2956184005f4860607e91672fce82164095dee6ebcbe57e5af883951a199c427"
	)
	raw, err := os.ReadFile("../../profiles/cli/talos-kubevirt-mvp-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := runnerprofile.Load(raw, runnerprofile.TalosMVP, enablement, platform)
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.Identity{Name: "admission-fixture", Namespace: "admission-fixture"}
	revision := digest.SHA256([]byte("contract revision"))
	fixture := digest.SHA256([]byte("execution fixture"))
	target := digest.SHA256([]byte("target cluster uid"))
	rendered, err := recipe.Render(identity, revision, fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target-access.yaml")
	if err := os.WriteFile(path, rendered.Files["target-access.yaml"], 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := submission.LoadTargetAccess(path, submission.TargetAccessExpected{
		ArtifactDigest: digest.SHA256(rendered.Files["target-access.yaml"]), ContractIdentity: identity,
		IntentRevision: revision, PlatformRevision: platform, ExecutionFixture: fixture,
		TargetIdentityDigest: target, WorkloadAuthority: target, Objects: rendered.TargetAccessObjects,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewFromPlan("system:serviceaccount:ok-system:target-writer", []string{"127.0.0.1/32"}, plan)
	if err != nil {
		t.Fatalf("verified current profile could not produce an offline policy: %v", err)
	}
	for index, object := range plan.Workload.Objects {
		requestObject := Object{Identity: object.Identity, Digest: object.Digest, Raw: object.Raw}
		review := validReviewForObject("system:serviceaccount:ok-system:target-writer", requestObject)
		response := sendReview(t, Handler(policy), review)
		if !response.Response.Allowed || response.Response.UID != review.Request.UID {
			t.Fatalf("verified profile AdmissionReview %d rejected or lost its UID: %#v", index, response)
		}
	}
	role := plan.Workload.Objects[2]
	var changed map[string]any
	if err := json.Unmarshal(role.Raw, &changed); err != nil {
		t.Fatal(err)
	}
	rules := changed["rules"].([]any)
	firstRule := rules[0].(map[string]any)
	firstRule["verbs"] = append(firstRule["verbs"].([]any), "escalate")
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	forged := validReviewForObject("system:serviceaccount:ok-system:target-writer", Object{Identity: role.Identity, Digest: role.Digest, Raw: changedRaw})
	denied := sendReview(t, Handler(policy), forged)
	if denied.Response.Allowed || denied.Response.UID != forged.Request.UID {
		t.Fatalf("same-name RBAC escalation was not denied: %#v", denied)
	}
	if policy.Digest() == "" {
		t.Fatal("candidate admission policy has no stable digest")
	}
}
