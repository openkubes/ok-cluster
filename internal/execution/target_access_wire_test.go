package execution

import (
	"encoding/json"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestTargetAccessDispatchWireRoundTripPreservesObjectsButNotVerification(t *testing.T) {
	dispatch := validTargetAccessDispatchForWireTest(t)
	raw, err := EncodeTargetAccessDispatch(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTargetAccessDispatch(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DispatchID != dispatch.DispatchID || decoded.ArtifactDigest != dispatch.ArtifactDigest || len(decoded.Plane.Objects) != submission.TargetAccessObjectCount {
		t.Fatalf("dispatch binding changed after wire round trip: %#v", decoded)
	}
	for index := range dispatch.Plane.Objects {
		if string(decoded.Plane.Objects[index].Raw) != string(dispatch.Plane.Objects[index].Raw) || decoded.Plane.Objects[index].Digest != dispatch.Plane.Objects[index].Digest {
			t.Fatalf("object %d was not preserved by the wire encoding", index)
		}
	}
	if decoded.Mutation.verifiedStageGrant {
		t.Fatal("wire decoding must never recreate the local stage-verification marker")
	}
	if _, err := EncodeTargetAccessDispatch(decoded); err == nil {
		t.Fatal("decoded untrusted request was re-encoded as a locally verified dispatch")
	}
}

func TestTargetAccessDispatchWireRejectsTamperedObjectAndUnknownField(t *testing.T) {
	dispatch := validTargetAccessDispatchForWireTest(t)
	raw, err := EncodeTargetAccessDispatch(dispatch)
	if err != nil {
		t.Fatal(err)
	}
	var wire targetAccessDispatchWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Plane.Objects[0].Raw = json.RawMessage(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"tampered"}}`)
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTargetAccessDispatch(tampered); err == nil {
		t.Fatal("tampered object bytes were accepted")
	}
	withUnknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err := DecodeTargetAccessDispatch(withUnknown); err == nil {
		t.Fatal("unknown wire fields were accepted")
	}
}

func TestTargetAccessDispatchWireRejectsOversizedContentsBeforeEncoding(t *testing.T) {
	dispatch := validTargetAccessDispatchForWireTest(t)
	dispatch.Plane.Objects[0].Raw = make(json.RawMessage, maximumTargetAccessDispatchBytes+1)
	if _, err := EncodeTargetAccessDispatch(dispatch); err == nil {
		t.Fatal("oversized object content was accepted by the encoder")
	}
}

func validTargetAccessDispatchForWireTest(t *testing.T) TargetAccessDispatch {
	t.Helper()
	plan := stagedPlan(t)
	stage, stageDigest, err := plan.Stage("target-access")
	if err != nil {
		t.Fatal(err)
	}
	request := stagedMutationRequest(t, plan, StageMutationBinding{
		PlanDigest: plan.PlanDigest, StageID: stage.ID, StageDigest: stageDigest,
		Operation: stage.GrantOperation, Authority: stage.Authority, ContractRevision: plan.IntentRevision,
	})
	request.verifiedStageGrant = true
	artifact, target := stagedSHA("0"), stagedSHA("e")
	kinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole"}
	objects := make([]submission.Object, len(kinds))
	for i, kind := range kinds {
		apiVersion := "v1"
		name := "object-" + string(rune('a'+i))
		namespace := ""
		collection := "/api/v1/namespaces"
		switch kind {
		case "ServiceAccount":
			namespace, collection = "kube-system", "/api/v1/namespaces/kube-system/serviceaccounts"
		case "Role":
			apiVersion, namespace, collection = "rbac.authorization.k8s.io/v1", "kube-system", "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/roles"
		case "RoleBinding":
			apiVersion, namespace, collection = "rbac.authorization.k8s.io/v1", "kube-system", "/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings"
		case "ClusterRole":
			apiVersion, collection = "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/clusterroles"
		case "ClusterRoleBinding":
			apiVersion, collection = "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
		}
		object := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name}}
		if namespace != "" {
			object["metadata"].(map[string]any)["namespace"] = namespace
		}
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		identity := projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Name: name, Namespace: namespace}
		objects[i] = submission.Object{Identity: identity, Digest: digest.SHA256(raw), CollectionPath: collection, ObjectPath: collection + "/" + name, Raw: raw}
	}
	dispatchID, err := targetAccessDispatchID(request, artifact, target)
	if err != nil {
		t.Fatal(err)
	}
	return TargetAccessDispatch{Mutation: request, DispatchID: dispatchID, ArtifactDigest: artifact,
		TargetIdentityDigest: target, Plane: submission.Plane{Identity: target, Role: "target-access-writer", Objects: objects}}
}
