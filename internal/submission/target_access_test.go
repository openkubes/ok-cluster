package submission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
)

func TestLoadTargetAccessBindsExactEightObjectSet(t *testing.T) {
	raw := targetAccessYAML()
	path := writeTargetAccessArtifact(t, raw)
	expected := targetAccessExpected(raw)
	plan, err := LoadTargetAccess(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != TargetAccessPlanFormat || plan.IntentRevision != expected.IntentRevision || plan.PlatformRevision != expected.PlatformRevision || plan.TargetIdentityDigest != expected.TargetIdentityDigest || plan.MutationAllowed {
		t.Fatalf("unexpected target-access plan: %#v", plan)
	}
	if plan.Workload.Identity != expected.TargetIdentityDigest || plan.Workload.Role != "target-access-writer" || len(plan.Workload.Objects) != 8 {
		t.Fatalf("unexpected target-access authority plane: %#v", plan.Workload)
	}
	for index, object := range plan.Workload.Objects {
		if object.Identity != expected.Objects[index] || !immutableDigestPattern.MatchString(object.Digest) || object.CollectionPath == "" || object.ObjectPath != object.CollectionPath+"/"+object.Identity.Name || len(object.Raw) == 0 {
			t.Fatalf("invalid target-access object %d: %#v", index+1, object)
		}
	}

	again, err := LoadTargetAccess(path, expected)
	if err != nil || again.ArtifactDigest != plan.ArtifactDigest || again.Workload.Objects[7].Digest != plan.Workload.Objects[7].Digest {
		t.Fatalf("target-access plan is not reproducible: %#v %v", again, err)
	}
}

func TestLoadTargetAccessFailsClosed(t *testing.T) {
	valid := targetAccessYAML()
	for name, mutate := range map[string]func([]byte) []byte{
		"missing object": func(raw []byte) []byte {
			marker := []byte("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: ok147-argocd-kube-system")
			return raw[:strings.Index(string(raw), string(marker))]
		},
		"wrong order": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "kind: ServiceAccount", "kind: Role", 1))
		},
		"wildcard permission": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "verbs: [get, list, watch]", "verbs: ['*']", 1))
		},
		"user subject": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "kind: ServiceAccount, name: ok147-argocd-manager", "kind: User, name: cluster-admin", 1))
		},
		"foreign role reference": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "name: ok147-argocd-platform-cluster\nsubjects:", "name: cluster-admin\nsubjects:", 1))
		},
		"runtime metadata": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "name: ok-observability\n  labels:", "name: ok-observability\n  uid: foreign\n  labels:", 1))
		},
		"unknown rule field": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "resources: [customresourcedefinitions]\n    verbs:", "resources: [customresourcedefinitions]\n    arbitrary: true\n    verbs:", 1))
		},
		"status": func(raw []byte) []byte { return append(raw, []byte("status: {}\n")...) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(append([]byte(nil), valid...))
			expected := targetAccessExpected(raw)
			if _, err := LoadTargetAccess(writeTargetAccessArtifact(t, raw), expected); err == nil {
				t.Fatal("unsafe target-access artifact was accepted")
			}
		})
	}

	expected := targetAccessExpected(valid)
	path := writeTargetAccessArtifact(t, valid)
	expected.ArtifactDigest = targetAccessSHA("0")
	if _, err := LoadTargetAccess(path, expected); err == nil {
		t.Fatal("changed target-access artifact digest was accepted")
	}

	expected = targetAccessExpected(valid)
	expected.WorkloadAuthority = targetAccessSHA("f")
	if _, err := LoadTargetAccess(path, expected); err == nil {
		t.Fatal("foreign target-access workload authority was accepted")
	}

	symlink := filepath.Join(t.TempDir(), "target-access.yaml")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargetAccess(symlink, targetAccessExpected(valid)); err == nil {
		t.Fatal("symlink target-access artifact was accepted")
	}
}

func targetAccessExpected(raw []byte) TargetAccessExpected {
	return TargetAccessExpected{
		ArtifactDigest: digest.SHA256(raw), ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision: targetAccessSHA("a"), PlatformRevision: targetAccessSHA("b"), ExecutionFixture: targetAccessSHA("c"),
		TargetIdentityDigest: targetAccessSHA("d"), WorkloadAuthority: targetAccessSHA("d"),
		Objects: []projection.ResourceIdentity{
			{APIVersion: "v1", Kind: "Namespace", Name: "ok-observability"},
			{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "kube-system", Name: "ok147-argocd-manager"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "ok147-argocd-platform-cluster"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding", Name: "ok147-argocd-platform-cluster"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "ok-observability", Name: "ok147-argocd-platform"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "ok-observability", Name: "ok147-argocd-platform"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role", Namespace: "kube-system", Name: "ok147-argocd-kube-system"},
			{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding", Namespace: "kube-system", Name: "ok147-argocd-kube-system"},
		},
	}
}

func writeTargetAccessArtifact(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target-access.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func targetAccessYAML() []byte {
	return []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: ok-observability
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ok147-argocd-manager
  namespace: kube-system
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ok147-argocd-platform-cluster
rules:
  - apiGroups: [apiextensions.k8s.io]
    resources: [customresourcedefinitions]
    verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ok147-argocd-platform-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ok147-argocd-platform-cluster
subjects:
  - {kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ok147-argocd-platform
  namespace: ok-observability
rules:
  - apiGroups: [""]
    resources: [configmaps, services]
    verbs: [get, list, watch, create, patch, update, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ok147-argocd-platform
  namespace: ok-observability
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ok147-argocd-platform
subjects:
  - {kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ok147-argocd-kube-system
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: [services]
    verbs: [get, list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ok147-argocd-kube-system
  namespace: kube-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ok147-argocd-kube-system
subjects:
  - {kind: ServiceAccount, name: ok147-argocd-manager, namespace: kube-system}
`)
}

func targetAccessSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
