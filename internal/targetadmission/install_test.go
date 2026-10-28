package targetadmission

import (
	"bytes"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

func TestRenderInstallSetIsImmutableDigestPinnedAndLeastPrivilege(t *testing.T) {
	image := "ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("a", 64)
	first, err := RenderInstallSet(image)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderInstallSet(image)
	if err != nil {
		t.Fatal(err)
	}
	if first.Format != InstallManifestFormat || len(first.Objects) != 6 || len(second.Objects) != len(first.Objects) {
		t.Fatalf("unexpected install set: %#v", first)
	}
	wantKinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Deployment", "Service"}
	objects := map[string]map[string]any{}
	for index, object := range first.Objects {
		if object.Kind != wantKinds[index] || object.Digest != digest.SHA256(object.Raw) || !bytes.Equal(object.Raw, second.Objects[index].Raw) {
			t.Fatalf("install object %d has invalid order, digest or stability", index)
		}
		var decoded map[string]any
		if err := yaml.Unmarshal(object.Raw, &decoded); err != nil {
			t.Fatal(err)
		}
		objects[object.Kind] = decoded
	}

	rules := objects["ClusterRole"]["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("identity reader RBAC should contain exactly two read rules: %#v", rules)
	}
	namespaceRule := rules[0].(map[string]any)
	if !sameStrings(namespaceRule["apiGroups"], []string{""}) || !sameStrings(namespaceRule["resources"], []string{"namespaces"}) || !sameStrings(namespaceRule["resourceNames"], []string{"kube-system"}) || !sameStrings(namespaceRule["verbs"], []string{"get"}) {
		t.Fatalf("identity reader RBAC is broader than one kube-system GET: %#v", namespaceRule)
	}
	versionRule := rules[1].(map[string]any)
	if !sameStrings(versionRule["nonResourceURLs"], []string{"/version"}) || !sameStrings(versionRule["verbs"], []string{"get"}) || len(versionRule) != 2 {
		t.Fatalf("version check RBAC is not restricted to GET /version: %#v", versionRule)
	}
	serviceAccount := objects["ServiceAccount"]
	if serviceAccount["automountServiceAccountToken"] != false {
		t.Fatal("default service-account token automount is enabled")
	}

	deployment := objects["Deployment"]["spec"].(map[string]any)
	if deployment["replicas"] != 1 || deployment["strategy"].(map[string]any)["type"] != "Recreate" {
		t.Fatal("deployment is not single-instance and non-overlapping")
	}
	pod := deployment["template"].(map[string]any)["spec"].(map[string]any)
	if pod["automountServiceAccountToken"] != false || pod["hostNetwork"] == true {
		t.Fatal("pod has broad default authority or host networking")
	}
	podSecurity := pod["securityContext"].(map[string]any)
	if podSecurity["runAsNonRoot"] != true || podSecurity["runAsUser"] != 65532 || podSecurity["runAsGroup"] != 65532 ||
		podSecurity["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
		t.Fatalf("pod security context is not restricted: %#v", podSecurity)
	}
	container := pod["containers"].([]any)[0].(map[string]any)
	if container["image"] != image || container["imagePullPolicy"] != "IfNotPresent" {
		t.Fatal("container image is not the exact immutable reference")
	}
	security := container["securityContext"].(map[string]any)
	capabilities := security["capabilities"].(map[string]any)
	if security["allowPrivilegeEscalation"] != false || security["readOnlyRootFilesystem"] != true ||
		!sameStrings(capabilities["drop"], []string{"ALL"}) {
		t.Fatal("container security context is not hardened")
	}
	resources := container["resources"].(map[string]any)
	requests := resources["requests"].(map[string]any)
	limits := resources["limits"].(map[string]any)
	if requests["cpu"] != "10m" || requests["memory"] != "32Mi" || limits["cpu"] != "500m" || limits["memory"] != "128Mi" {
		t.Fatalf("container resource bounds changed unexpectedly: %#v", resources)
	}
	mounts := container["volumeMounts"].([]any)
	if len(mounts) != 4 {
		t.Fatalf("expected only the four explicit read-only inputs, got %#v", mounts)
	}
	for _, value := range mounts {
		mount := value.(map[string]any)
		if mount["readOnly"] != true {
			t.Fatalf("non-read-only input mount: %#v", mount)
		}
	}
	volumes := pod["volumes"].([]any)
	if len(volumes) != 4 {
		t.Fatalf("unexpected pod volumes: %#v", volumes)
	}
	var projectedTokenLifetime any
	for _, value := range volumes {
		volume := value.(map[string]any)
		if projected, ok := volume["projected"].(map[string]any); ok {
			sources := projected["sources"].([]any)
			if len(sources) != 2 {
				t.Fatalf("projected identity volume has unexpected sources: %#v", sources)
			}
			projectedTokenLifetime = sources[0].(map[string]any)["serviceAccountToken"].(map[string]any)["expirationSeconds"]
		}
	}
	if projectedTokenLifetime != 600 {
		t.Fatalf("target identity token is not short-lived: %v", projectedTokenLifetime)
	}
	for _, probeName := range []string{"readinessProbe", "livenessProbe"} {
		probe := container[probeName].(map[string]any)
		httpGet := probe["httpGet"].(map[string]any)
		if httpGet["scheme"] != "HTTPS" || httpGet["path"] != HealthPath || httpGet["port"] != "https" {
			t.Fatalf("%s does not use the bounded HTTPS health endpoint: %#v", probeName, probe)
		}
		if _, exists := probe["tcpSocket"]; exists {
			t.Fatalf("%s still relies on TCP-only readiness", probeName)
		}
	}

	if _, exists := objects["Secret"]; exists {
		t.Fatal("renderer must not manufacture policy or credential Secret data")
	}
	if _, exists := objects["ValidatingWebhookConfiguration"]; exists {
		t.Fatal("webhook activation must remain a separate reviewed step")
	}
	service := objects["Service"]["spec"].(map[string]any)
	if service["type"] != "ClusterIP" {
		t.Fatal("admission service is externally exposed")
	}
}

func TestRenderInstallSetRejectsMutableOrUnqualifiedImages(t *testing.T) {
	for _, image := range []string{
		"openkubes/ok-target-admission:latest",
		"ghcr.io/openkubes/ok-target-admission:v1.0.0",
		"ghcr.io/openkubes/ok-target-admission@sha256:" + strings.Repeat("A", 64),
		"ghcr.io/openkubes/ok-target-admission@sha256:deadbeef",
	} {
		if _, err := RenderInstallSet(image); err == nil {
			t.Errorf("mutable or invalid image accepted: %q", image)
		}
	}
}

func sameStrings(value any, expected []string) bool {
	actualValues, ok := value.([]any)
	if !ok || len(actualValues) != len(expected) {
		return false
	}
	for index := range expected {
		if actualValues[index] != expected[index] {
			return false
		}
	}
	return true
}
