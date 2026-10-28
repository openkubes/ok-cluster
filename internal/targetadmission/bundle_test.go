package targetadmission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestSignedBundleRequiresIndependentKeyAndExactRuntimeTarget(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := policyConfig()
	target := TargetBinding{CAPIClusterUID: "target-cluster-uid", KubeSystemNamespaceUID: "kube-system-uid"}
	raw, err := SignBundle(config, target, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	policy, verifiedTarget, err := VerifyBundle(raw, publicKey)
	if err != nil || policy == nil || verifiedTarget != target {
		t.Fatalf("valid signed bundle rejected: %v", err)
	}
	if err := VerifyTargetBinding(verifiedTarget, "kube-system-uid"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTargetBinding(verifiedTarget, "replacement-kube-system-uid"); err == nil {
		t.Fatal("same-name replacement cluster activated the bundle")
	}
	if _, _, err := VerifyBundle(raw, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))); err == nil {
		t.Fatal("untrusted signer was accepted")
	}

	var bundle SignedBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Target.KubeSystemNamespaceUID = "foreign-uid"
	tampered, _ := json.Marshal(bundle)
	if _, _, err := VerifyBundle(tampered, publicKey); err == nil {
		t.Fatal("tampered target binding was accepted")
	}

	bundle = SignedBundle{}
	_ = json.Unmarshal(raw, &bundle)
	bundle.Policy.Objects[0].Raw[0] ^= 0xff
	tampered, _ = json.Marshal(bundle)
	if _, _, err := VerifyBundle(tampered, publicKey); err == nil {
		t.Fatal("tampered policy object was accepted")
	}

	bundle = SignedBundle{}
	_ = json.Unmarshal(raw, &bundle)
	bundle.Policy.APIServerSourceCIDRs = []string{"0.0.0.0/0"}
	tampered, _ = json.Marshal(bundle)
	if _, _, err := VerifyBundle(tampered, publicKey); err == nil {
		t.Fatal("tampered API-server source CIDR allowlist was accepted")
	}
}

func TestSignBundleRejectsMismatchedRuntimeIdentity(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignBundle(policyConfig(), TargetBinding{CAPIClusterUID: "different", KubeSystemNamespaceUID: "uid"}, privateKey); err == nil {
		t.Fatal("bundle signer accepted target identity not bound by the plan")
	}
}
