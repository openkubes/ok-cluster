package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeBindingWriterCreatesOneVerifiedPrivateFile(t *testing.T) {
	material, err := BuildRuntimeBindingMaterial(runtimeBindingMaterialConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "runtime-binding.json")
	writer, err := OpenRuntimeBindingWriter(material, path)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.Write()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || receipt.State != "WRITTEN_VERIFIED" || receipt.FileMode != "0600" || receipt.FileSize <= 0 || receipt.KubernetesMutationAllowed || info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime binding persistence differs: %#v mode=%v err=%v", receipt, info.Mode(), err)
	}
	if _, err := writer.Write(); err == nil {
		t.Fatal("single-use runtime binding writer wrote twice")
	}
}

func TestRuntimeBindingWriterFailsClosedOnUnsafeOutput(t *testing.T) {
	material, err := BuildRuntimeBindingMaterial(runtimeBindingMaterialConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "existing.json")
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Chmod(filepath.Dir(public), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":      "runtime-binding.json",
		"existing":      existing,
		"public parent": public,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenRuntimeBindingWriter(material, path); err == nil {
				t.Fatal("unsafe runtime binding output was accepted")
			}
		})
	}
	if _, err := OpenRuntimeBindingWriter(VerifiedRuntimeBindingMaterial{}, filepath.Join(root, "invalid.json")); err == nil {
		t.Fatal("unverified runtime binding material opened a writer")
	}
}
