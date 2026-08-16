package runner

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSubmissionStageRuntimeHasTokenlessIdentityAndNoRBAC(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "..", "deploy", "contract-executor-stage-runtime.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := []map[string]any{}
	for {
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if len(object) != 0 {
			objects = append(objects, object)
		}
	}
	if len(objects) != 1 || objects[0]["apiVersion"] != "v1" || objects[0]["kind"] != "ServiceAccount" {
		t.Fatalf("runtime prerequisite contains an unexpected object set: %#v", objects)
	}
	serviceAccount := objects[0]
	metadata := objectAt(t, serviceAccount, "metadata")
	if metadata["name"] != "ok147-contract-executor-runtime" || metadata["namespace"] != submissionStageInputNamespace {
		t.Fatalf("unexpected runtime identity: %#v", metadata)
	}
	labels := objectAt(t, metadata, "labels")
	if labels["openkubes.io/runtime-boundary"] != "submission-stage" {
		t.Fatalf("runtime boundary label is absent: %#v", labels)
	}
	if serviceAccount["automountServiceAccountToken"] != false {
		t.Fatal("submission runtime would receive an implicit Kubernetes credential")
	}
	for _, forbidden := range []string{"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Secret"} {
		if bytes.Contains(raw, []byte("kind: "+forbidden+"\n")) {
			t.Fatalf("runtime prerequisite unexpectedly contains %s", forbidden)
		}
	}
}
