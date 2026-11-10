package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validClusterRequestYAML = `apiVersion: cli.openkubes.io/v1alpha1
kind: ClusterRequest
metadata:
  name: preview-one
spec:
  profile: talos-kubevirt-reference
  network:
    endpoint: auto
    podCIDR: auto
    serviceCIDR: auto
`

func writeClusterPlanRequest(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClusterPlanValidAndDeterministic(t *testing.T) {
	path := writeClusterPlanRequest(t, validClusterRequestYAML)
	var first, second bytes.Buffer
	if err := runClusterPlan([]string{"-f", path}, &first, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := runClusterPlan([]string{"--file", path}, &second, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("plan output is not deterministic")
	}
	for _, expected := range []string{
		"Request: preview-one", "talos-kubevirt-reference", "trusted administrator Make workflow",
		"make new CLUSTER=preview-one TYPE=talos", "make bootstrap CLUSTER=preview-one",
		"v1.34.1", "v1.9.6", "auto (unresolved", "does not authorize or execute",
		"Cilium v1.19.6", clusterRequestSchematic,
	} {
		if !strings.Contains(first.String(), expected) {
			t.Fatalf("plan missing %q:\n%s", expected, first.String())
		}
	}
}

func TestClusterPlanRejectsInvalidRequests(t *testing.T) {
	cases := map[string]string{
		"wrong api version":             strings.Replace(validClusterRequestYAML, "cli.openkubes.io/v1alpha1", "cli.openkubes.io/v2", 1),
		"wrong kind":                    strings.Replace(validClusterRequestYAML, "ClusterRequest", "Cluster", 1),
		"unsupported profile":           strings.Replace(validClusterRequestYAML, "talos-kubevirt-reference", "flatcar", 1),
		"unknown field":                 validClusterRequestYAML + "  surprise: true\n",
		"duplicate key":                 strings.Replace(validClusterRequestYAML, "  profile: talos-kubevirt-reference", "  profile: talos-kubevirt-reference\n  profile: talos-kubevirt-reference", 1),
		"alias":                         strings.Replace(validClusterRequestYAML, "  profile: talos-kubevirt-reference", "  profile: &profile talos-kubevirt-reference\n  profileCopy: *profile", 1),
		"multiple documents":            validClusterRequestYAML + "---\napiVersion: cli.openkubes.io/v1alpha1\n",
		"control plane replicas":        strings.Replace(validClusterRequestYAML, "  profile:", "  controlPlane:\n    replicas: 3\n  profile:", 1),
		"worker replicas zero":          strings.Replace(validClusterRequestYAML, "  profile:", "  workers:\n    replicas: 0\n  profile:", 1),
		"invalid version":               strings.Replace(validClusterRequestYAML, "  network:", "  versions:\n    kubernetes: latest\n  network:", 1),
		"invalid endpoint":              strings.Replace(validClusterRequestYAML, "endpoint: auto", "endpoint: not-an-address", 1),
		"explicit pod cidr unsupported": strings.Replace(validClusterRequestYAML, "podCIDR: auto", "podCIDR: 10.10.0.0/16", 1),
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeClusterPlanRequest(t, contents)
			if err := runClusterPlan([]string{"-f", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestClusterPlanMapsSupportedMakeOverrides(t *testing.T) {
	request := strings.Replace(validClusterRequestYAML, "  profile: talos-kubevirt-reference", `  profile: talos-kubevirt-reference
  workers:
    replicas: 3
  versions:
    kubernetes: v1.35.2
    talos: v1.10.1`, 1)
	path := writeClusterPlanRequest(t, request)
	var output bytes.Buffer
	if err := runClusterPlan([]string{"-f", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Workers:       3 replica(s)", "v1.35.2", "v1.10.1", "WORKERS=3", "K8S_VERSION=v1.35.2", "TALOS_VERSION=v1.10.1"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("plan does not map supported Make override %q:\n%s", expected, output.String())
		}
	}
}

func TestClusterPlanRejectsDuplicateInputFlags(t *testing.T) {
	path := writeClusterPlanRequest(t, validClusterRequestYAML)
	if err := runClusterPlan([]string{"-f", path, "--file", path}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("duplicate file flags were accepted")
	}
}

func TestClusterPlanHelpOutput(t *testing.T) {
	var output bytes.Buffer
	if err := runContext(nil, []string{"cluster", "plan", "--help"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ok cluster plan -f <cluster.yaml>", "ClusterRequest", "never invokes Make, kubectl", "writes no files"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("plan help missing %q:\n%s", expected, output.String())
		}
	}
}

func TestClusterPlanRejectsUnsafeInputFiles(t *testing.T) {
	valid := writeClusterPlanRequest(t, validClusterRequestYAML)
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link.yaml")
		if err := os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readClusterRequest(link); err == nil {
			t.Fatal("symlink input was accepted")
		}
	})
	t.Run("non regular", func(t *testing.T) {
		if _, err := readClusterRequest(t.TempDir()); err == nil {
			t.Fatal("directory input was accepted")
		}
	})
	t.Run("over 64 KiB", func(t *testing.T) {
		path := writeClusterPlanRequest(t, validClusterRequestYAML+fmt.Sprintf("#%s\n", strings.Repeat("x", 64*1024)))
		if _, err := readClusterRequest(path); err == nil {
			t.Fatal("oversized input was accepted")
		}
	})
}

func TestClusterPlanRejectsMergeKeys(t *testing.T) {
	request := strings.Replace(validClusterRequestYAML, "  network:\n", "  network:\n    <<: {endpoint: auto}\n", 1)
	if _, err := readClusterRequest(writeClusterPlanRequest(t, request)); err == nil {
		t.Fatal("YAML merge key was accepted")
	}
}

func TestClusterPlanWorkerCountBoundaries(t *testing.T) {
	for _, count := range []int{1, 10} {
		t.Run(fmt.Sprintf("accept_%d", count), func(t *testing.T) {
			request := strings.Replace(validClusterRequestYAML, "  profile:", fmt.Sprintf("  workers:\n    replicas: %d\n  profile:", count), 1)
			if _, err := readClusterRequest(writeClusterPlanRequest(t, request)); err != nil {
				t.Fatalf("worker count %d rejected: %v", count, err)
			}
		})
	}
	for _, count := range []int{0, 11} {
		t.Run(fmt.Sprintf("reject_%d", count), func(t *testing.T) {
			request := strings.Replace(validClusterRequestYAML, "  profile:", fmt.Sprintf("  workers:\n    replicas: %d\n  profile:", count), 1)
			if _, err := readClusterRequest(writeClusterPlanRequest(t, request)); err == nil {
				t.Fatalf("worker count %d accepted", count)
			}
		})
	}
}

func TestClusterPlanCommandRoute(t *testing.T) {
	path := writeClusterPlanRequest(t, validClusterRequestYAML)
	var output bytes.Buffer
	if err := runContext(nil, []string{"cluster", "plan", "-f", path}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "OpenKubes Cluster Plan") {
		t.Fatalf("plan command was not routed: %s", output.String())
	}
}

func TestClusterPlanDoesNotExecuteExternalCommandsOrWriteFiles(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "cluster.yaml")
	if err := os.WriteFile(requestPath, []byte(validClusterRequestYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "external-command-ran")
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"make", "kubectl", "python", "python3", "render.py"} {
		script := "#!/bin/sh\nprintf called > " + marker + "\n"
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir)
	var output bytes.Buffer
	if err := runClusterPlan([]string{"-f", requestPath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("plan invoked an external command")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // request and fake-command directory only
		t.Fatalf("plan wrote unexpected files: %v", entries)
	}
}
