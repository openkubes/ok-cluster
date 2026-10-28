package targetadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildOfflineActivationPlanIsDigestBoundAndNeverClaimsActivation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := policyConfig()
	target := TargetBinding{CAPIClusterUID: "private-capi-uid", KubeSystemNamespaceUID: "private-namespace-uid"}
	config.TargetIdentityDigest = digest.SHA256([]byte(target.CAPIClusterUID))
	bundle, err := SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _ := testCertificates(t, InstallServiceDNS)
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("b", 64)
	plan, err := BuildOfflineActivationPlan(bundle, publicKey, ca, image)
	if err != nil {
		t.Fatal(err)
	}
	changedNetworkConfig := config
	changedNetworkConfig.APIServerSourceCIDRs = []string{"192.0.2.0/24"}
	changedNetworkBundle, err := SignBundle(changedNetworkConfig, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	changedNetworkPlan, err := BuildOfflineActivationPlan(changedNetworkBundle, publicKey, ca, image)
	if err != nil {
		t.Fatal(err)
	}
	if changedNetworkPlan.PolicyDigest == plan.PolicyDigest || changedNetworkPlan.PlanDigest == plan.PlanDigest {
		t.Fatal("activation identity did not change when the independently signed API-server CIDRs changed")
	}
	if err := VerifyOfflineActivationPlan(plan, bundle, publicKey, ca); err != nil {
		t.Fatalf("independent plan regeneration rejected exact plan: %v", err)
	}
	if plan.Format != ActivationPlanFormat || plan.State != "PLAN_ONLY_AWAITING_TARGET_CHECKS" || plan.PlanDigest == "" ||
		plan.PolicyDigest == "" || plan.TargetBindingDigest == "" || plan.WebhookConfigurationDigest != plan.Activation.Digest ||
		plan.KubernetesVersionVerified || !plan.TargetIdentityRecheckNeeded || plan.APIAccessed || plan.MutationAllowed || plan.WebhookActive {
		t.Fatalf("plan overstates verification or activation state: %#v", plan)
	}
	if len(plan.Scaffold) != 6 || plan.Activation.Kind != "ValidatingWebhookConfiguration" {
		t.Fatalf("unexpected two-phase plan: scaffold=%d activation=%s", len(plan.Scaffold), plan.Activation.Kind)
	}
	if plan.Scaffold[0].Kind != "Namespace" || plan.Scaffold[len(plan.Scaffold)-1].Kind != "Service" {
		t.Fatalf("scaffold object order is unexpected: %#v", plan.Scaffold)
	}
	for _, item := range plan.Scaffold {
		if item.Digest != digest.SHA256([]byte(item.Manifest)) || strings.Contains(item.Manifest, target.CAPIClusterUID) || strings.Contains(item.Manifest, target.KubeSystemNamespaceUID) {
			t.Fatalf("invalid or identity-leaking scaffold object %s/%s", item.Kind, item.Name)
		}
	}
	if plan.Activation.Digest != digest.SHA256([]byte(plan.Activation.Manifest)) || strings.Contains(plan.Activation.Manifest, target.CAPIClusterUID) || strings.Contains(plan.Activation.Manifest, target.KubeSystemNamespaceUID) {
		t.Fatal("activation object digest invalid or raw target identity leaked")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := VerifyOfflineActivationPlanDocument(encoded, bundle, publicKey, ca); err != nil || decoded.PlanDigest != plan.PlanDigest {
		t.Fatalf("strict activation-plan document verification failed: %#v %v", decoded, err)
	}
	if _, err := VerifyOfflineActivationPlanDocument(append(encoded[:len(encoded)-1], []byte(",\"unexpected\":true}")...), bundle, publicKey, ca); err == nil {
		t.Fatal("activation-plan document with an unknown field accepted")
	}
	if strings.Contains(string(encoded), target.CAPIClusterUID) || strings.Contains(string(encoded), target.KubeSystemNamespaceUID) {
		t.Fatal("offline plan exposed raw target UIDs")
	}

	changed := plan
	changed.Scaffold = append([]PlannedObject(nil), plan.Scaffold...)
	changed.Scaffold[0].Manifest += "# tampered\n"
	if err := VerifyOfflineActivationPlan(changed, bundle, publicKey, ca); err == nil {
		t.Fatal("tampered plan accepted by independent regeneration")
	}
}

func TestBuildOfflineActivationPlanRejectsUntrustedInputs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := policyConfig()
	target := TargetBinding{CAPIClusterUID: "capi-uid", KubeSystemNamespaceUID: "namespace-uid"}
	config.TargetIdentityDigest = digest.SHA256([]byte(target.CAPIClusterUID))
	bundle, err := SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _ := testCertificates(t, "ca.example")
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("c", 64)
	if _, err := BuildOfflineActivationPlan(bundle, ed25519.PublicKey(strings.Repeat("x", ed25519.PublicKeySize)), ca, image); err == nil {
		t.Fatal("untrusted policy signer accepted")
	}
	if _, err := BuildOfflineActivationPlan(bundle, publicKey, []byte("not a CA"), image); err == nil {
		t.Fatal("invalid webhook CA accepted")
	}
	if _, err := BuildOfflineActivationPlan(bundle, publicKey, ca, "ghcr.io/openkubes/ok-target-admission:latest"); err == nil {
		t.Fatal("mutable deployment image accepted")
	}
}
