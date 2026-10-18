package stageplan

import (
	"bytes"
	"testing"
)

func TestBuildFreshBareClusterPlanUsesExistingOwnerSequence(t *testing.T) {
	want := expected()
	want.CompletionMode = CompletionModeBareClusterMVP
	inputs := map[string]string{}
	for _, name := range []string{"projection.provider-prerequisites", "projection.cluster-lifecycle", "stage.provider-access", "stage.lifecycle-observation", "stage.enablement", "stage.network-observation", "stage.runtime-binding", "stage.target-access"} {
		inputs[name] = sha("1")
	}
	raw, binding, err := BuildBareCluster(want, inputs)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Verify(raw, want)
	if err != nil || loaded.PlanDigest != binding.PlanDigest || len(loaded.Stages) != 7 {
		t.Fatalf("builder bypassed verifier: %v", err)
	}
	again, _, err := BuildBareCluster(want, inputs)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("fresh plan is not deterministic")
	}
	if bytes.Contains(raw, []byte("executionAttemptDigest")) || bytes.Contains(raw, []byte("recoverySourcePlanDigest")) || bytes.Contains(raw, []byte("deferred-mvp")) {
		t.Fatal("builder invented retry/recovery/relaxed evidence")
	}
	delete(inputs, "stage.runtime-binding")
	if _, _, err := BuildBareCluster(want, inputs); err == nil {
		t.Fatal("missing runtime requirements accepted")
	}
	inputs["stage.runtime-binding"] = sha("1")
	inputs["unexpected"] = sha("1")
	if _, _, err := BuildBareCluster(want, inputs); err == nil {
		t.Fatal("extra authority input accepted")
	}
	delete(inputs, "unexpected")
	for _, mutate := range []func(*Expected){func(x *Expected) { x.ExecutionAttemptDigest = sha("2") }, func(x *Expected) { x.RecoverySourcePlanDigest = sha("2") }, func(x *Expected) { x.NetworkObservationMode = "deferred-mvp/v1" }, func(x *Expected) { x.CompletionMode = "" }} {
		bad := want
		mutate(&bad)
		if _, _, err := BuildBareCluster(bad, inputs); err == nil {
			t.Fatal("non-fresh scope accepted")
		}
	}
}
