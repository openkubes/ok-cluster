package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClusterIntentTargetReferencesArePairedAndStrict(t *testing.T) {
	for _, fields := range []string{
		"  management: {kubeconfig: ~/.kube/mgmt}\n",
		"  management: {kubeconfig: ''}\n  infrastructure: {kubeconfig: infra}\n",
		"  management: {kubeconfig: mgmt, currentContext: accidental}\n  infrastructure: {kubeconfig: infra}\n",
		"  management: {kubeconfig: mgmt, context: 123}\n  infrastructure: {kubeconfig: infra}\n",
	} {
		path := intentFixture(t, func(raw string) string { return strings.Replace(raw, "  profile:", fields+"  profile:", 1) })
		if _, err := readClusterIntent(path); err == nil {
			t.Fatal("ambiguous reference schema accepted")
		}
	}
	path := intentFixture(t, func(raw string) string {
		return strings.Replace(raw, "  profile:", "  management: {kubeconfig: ~/.kube/mgmt}\n  infrastructure: {kubeconfig: relative/infra, context: chosen}\n  profile:", 1)
	})
	intent, err := readClusterIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Spec.Infrastructure.Context != "chosen" {
		t.Fatal("lost explicit context")
	}
}

func TestClusterIntentWithoutReferencesKeepsNormalizedIdentity(t *testing.T) {
	intent, err := readClusterIntent(intentFixture(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"apiVersion":"cli.openkubes.io/v1alpha1","kind":"Cluster","metadata":{"name":"my-cluster"},"spec":{"profile":"talos-kubevirt-mvp","network":{"endpoint":"192.0.2.10","podCIDR":"10.42.0.0/16","serviceCIDR":"10.96.0.0/20"}}}`
	if string(raw) != expected {
		t.Fatalf("changed legacy intent identity: %s", raw)
	}
	binding, _ := json.Marshal(clusterIntentBindingReceipt{})
	if strings.Contains(string(binding), `"targets"`) {
		t.Fatal("nil targets changed old binding receipt shape")
	}
}
