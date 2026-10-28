package targetadmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func TestPolicyAdmitsOnlyExactCreateByBoundWriter(t *testing.T) {
	config := policyConfig()
	policy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(policy.Digest(), "sha256:") {
		t.Fatalf("policy digest missing: %q", policy.Digest())
	}
	for i, object := range config.Objects {
		// JSON whitespace is not semantically significant; object content is.
		var pretty any
		if err := json.Unmarshal(object.Raw, &pretty); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.MarshalIndent(pretty, "", "  ")
		if err := policy.AdmitCreate(Request{Operation: "CREATE", Username: config.WriterUsername, Object: raw}); err != nil {
			t.Fatalf("exact object %d denied: %v", i, err)
		}
	}

	target := config.Objects[2]
	for name, request := range map[string]Request{
		"wrong actor":      {Operation: "CREATE", Username: "system:serviceaccount:other:writer", Object: target.Raw},
		"update":           {Operation: "UPDATE", Username: config.WriterUsername, Object: target.Raw},
		"delete":           {Operation: "DELETE", Username: config.WriterUsername, Object: target.Raw},
		"extra field":      {Operation: "CREATE", Username: config.WriterUsername, Object: []byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"target-2"},"rules":[],"aggregationRule":{"clusterRoleSelectors":[]}}`)},
		"unknown identity": {Operation: "CREATE", Username: config.WriterUsername, Object: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"unexpected"}}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.AdmitCreate(request); err == nil {
				t.Fatal("unapproved admission request was accepted")
			}
		})
	}
}

func TestPolicyIsImmutableAndBindsTargetAndCompleteObjectSet(t *testing.T) {
	config := policyConfig()
	policy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), config.Objects[0].Raw...)
	config.Objects[0].Raw[0] ^= 0xff
	if err := policy.AdmitCreate(Request{Operation: "CREATE", Username: "system:serviceaccount:ok-system:target-writer", Object: original}); err != nil {
		t.Fatalf("caller mutation changed compiled policy: %v", err)
	}
	changedTarget := policyConfig()
	changedTarget.TargetIdentityDigest = digest.SHA256([]byte("different-target"))
	other, err := New(changedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest() == policy.Digest() {
		t.Fatal("compiled policy digest did not bind target identity")
	}
	plan := planFromConfig(policyConfig())
	if _, err := NewFromPlan("system:serviceaccount:ok-system:target-writer", []string{"127.0.0.1/32"}, plan); err != nil {
		t.Fatalf("exact target-access plan was rejected: %v", err)
	}
	for name, mutate := range map[string]func(*submission.TargetAccessPlan){
		"authorizing plan": func(value *submission.TargetAccessPlan) { value.MutationAllowed = true },
		"wrong workload identity": func(value *submission.TargetAccessPlan) {
			value.Workload.Identity = digest.SHA256([]byte("wrong-target"))
		},
		"wrong workload role": func(value *submission.TargetAccessPlan) { value.Workload.Role = "admin" },
		"wrong object path":   func(value *submission.TargetAccessPlan) { value.Workload.Objects[0].ObjectPath = "/elsewhere" },
	} {
		t.Run("plan/"+name, func(t *testing.T) {
			candidate := planFromConfig(policyConfig())
			mutate(&candidate)
			if _, err := NewFromPlan("system:serviceaccount:ok-system:target-writer", []string{"127.0.0.1/32"}, candidate); err == nil {
				t.Fatal("invalid target-access plan was accepted")
			}
		})
	}
	for _, mutate := range []func(*Config){
		func(value *Config) { value.Objects = value.Objects[:len(value.Objects)-1] },
		func(value *Config) { value.Objects[1].Identity = value.Objects[0].Identity },
		func(value *Config) { value.Objects[0].Digest = digest.SHA256([]byte("wrong")) },
		func(value *Config) { value.WriterUsername = "system:serviceaccount::" },
	} {
		candidate := policyConfig()
		mutate(&candidate)
		if _, err := New(candidate); err == nil {
			t.Fatal("invalid trusted policy configuration was accepted")
		}
	}
}

func policyConfig() Config {
	config := Config{
		WriterUsername:       "system:serviceaccount:ok-system:target-writer",
		ArtifactDigest:       digest.SHA256([]byte("artifact")),
		IntentRevision:       digest.SHA256([]byte("intent")),
		PlatformRevision:     digest.SHA256([]byte("platform")),
		ExecutionFixture:     digest.SHA256([]byte("fixture")),
		TargetIdentityDigest: digest.SHA256([]byte("target-cluster-uid")),
		APIServerSourceCIDRs: []string{"127.0.0.1/32"},
		Objects:              make([]Object, len(stageSevenKinds)),
	}
	for i, kind := range stageSevenKinds {
		identity := projection.ResourceIdentity{APIVersion: stageSevenAPIVersions[i], Kind: kind, Name: "target-" + string(rune('a'+i))}
		if kind == "ServiceAccount" || kind == "Role" || kind == "RoleBinding" {
			identity.Namespace = "ok-observability"
		}
		value := map[string]any{
			"apiVersion": identity.APIVersion,
			"kind":       identity.Kind,
			"metadata":   map[string]any{"name": identity.Name},
		}
		if identity.Namespace != "" {
			value["metadata"].(map[string]any)["namespace"] = identity.Namespace
		}
		raw, _ := json.Marshal(value)
		config.Objects[i] = Object{Identity: identity, Digest: digest.SHA256(raw), Raw: raw}
	}
	return config
}

func TestPolicyRequiresCanonicalNonOverlappingAPIServerCIDRs(t *testing.T) {
	for _, cidrs := range [][]string{
		{},
		{"127.0.0.1/32", "127.0.0.0/8"},
		{"127.0.0.0/8", "127.0.0.1/32"},
		{"127.0.0.1/24"},
		{"bad"},
		{"0.0.0.0/0"},
		{"::/0"},
	} {
		candidate := policyConfig()
		candidate.APIServerSourceCIDRs = cidrs
		if _, err := New(candidate); err == nil {
			t.Errorf("invalid source CIDRs accepted: %#v", cidrs)
		}
	}
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		remote string
		want   bool
	}{
		{"127.0.0.1:8443", true},
		{"127.0.0.2:8443", false},
		{"[::1]:8443", false},
		{"not-an-ip:8443", false},
		{"127.0.0.1", false},
	} {
		if got := policy.AllowsAPIServerPeer(tc.remote); got != tc.want {
			t.Errorf("AllowsAPIServerPeer(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
}

func planFromConfig(config Config) submission.TargetAccessPlan {
	objects := make([]submission.Object, len(config.Objects))
	for i, object := range config.Objects {
		collectionPath := "/api/v1/namespaces"
		if object.Identity.APIVersion == "rbac.authorization.k8s.io/v1" {
			collectionPath = "/apis/rbac.authorization.k8s.io/v1/clusterroles"
			if object.Identity.Kind == "Role" {
				collectionPath = "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/roles"
			} else if object.Identity.Kind == "RoleBinding" {
				collectionPath = "/apis/rbac.authorization.k8s.io/v1/namespaces/ok-observability/rolebindings"
			} else if object.Identity.Kind == "ClusterRoleBinding" {
				collectionPath = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
			}
		} else if object.Identity.Kind == "ServiceAccount" {
			collectionPath = "/api/v1/namespaces/ok-observability/serviceaccounts"
		}
		objects[i] = submission.Object{
			Identity: object.Identity, Digest: object.Digest, Raw: append([]byte(nil), object.Raw...),
			CollectionPath: collectionPath, ObjectPath: collectionPath + "/" + object.Identity.Name,
		}
	}
	return submission.TargetAccessPlan{
		Format: submission.TargetAccessPlanFormat, ArtifactDigest: config.ArtifactDigest,
		IntentRevision: config.IntentRevision, PlatformRevision: config.PlatformRevision,
		ExecutionFixture: config.ExecutionFixture, TargetIdentityDigest: config.TargetIdentityDigest,
		Workload: submission.Plane{Identity: config.TargetIdentityDigest, Role: "target-access-writer", Objects: objects},
	}
}
