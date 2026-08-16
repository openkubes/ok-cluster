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

func TestLoadEnablementVerifiesOneExternallyRenderedHCP(t *testing.T) {
	raw := enablementYAML()
	path := writeEnablement(t, raw)
	plan, err := LoadEnablement(path, enablementExpected(raw))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != EnablementPlanFormat || plan.MutationAllowed || plan.IntentRevision != enablementSHA("1") || plan.EnablementRevision != enablementSHA("2") || plan.ExecutionFixture != enablementSHA("3") || plan.ArtifactDigest != digest.SHA256(raw) {
		t.Fatalf("unexpected enablement plan: %#v", plan)
	}
	if plan.Management.Identity != "ok-mgmt" || plan.Management.Role != "enablement-desired-state-writer" || len(plan.Management.Objects) != 1 {
		t.Fatalf("unexpected enablement plane: %#v", plan.Management)
	}
	object := plan.Management.Objects[0]
	if object.Identity.Kind != "HelmChartProxy" || object.CollectionPath != "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok147/helmchartproxies" || !immutableDigestPattern.MatchString(object.Digest) || len(object.Raw) == 0 {
		t.Fatalf("unexpected enablement object: %#v", object)
	}
}

func TestLoadEnablementFailsClosed(t *testing.T) {
	valid := enablementYAML()
	tests := map[string]struct {
		raw     []byte
		mutate  func(*EnablementExpected)
		symlink bool
	}{
		"artifact digest":          {raw: append(append([]byte{}, valid...), '\n'), mutate: func(expected *EnablementExpected) { expected.ArtifactDigest = digest.SHA256(valid) }},
		"wrong E":                  {raw: []byte(strings.Replace(string(valid), enablementSHA("2"), enablementSHA("4"), 1))},
		"wrong fixture":            {raw: []byte(strings.Replace(string(valid), enablementSHA("3"), enablementSHA("4"), 1))},
		"missing contract carrier": {raw: []byte(strings.Replace(string(valid), "    openkubes.io/contract-name: disposable-ok147\n", "", 1))},
		"mutable repository":       {raw: []byte(strings.Replace(string(valid), "oci://quay.io/cilium/charts", "https://example.invalid/charts", 1))},
		"mutable version":          {raw: []byte(strings.Replace(string(valid), "version: 1.19.6", "version: latest", 1))},
		"non-continuous":           {raw: []byte(strings.Replace(string(valid), "reconcileStrategy: Continuous", "reconcileStrategy: Once", 1))},
		"status":                   {raw: append(append([]byte{}, valid...), []byte("status: {}\n")...)},
		"multiple objects":         {raw: append(append(append([]byte{}, valid...), []byte("---\n")...), valid...)},
		"foreign identity":         {raw: valid, mutate: func(expected *EnablementExpected) { expected.ObjectIdentity.Name = "other-cilium" }},
		"symlink":                  {raw: valid, symlink: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeEnablement(t, test.raw)
			if test.symlink {
				link := filepath.Join(t.TempDir(), "enablement.yaml")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			}
			expected := enablementExpected(test.raw)
			if test.mutate != nil {
				test.mutate(&expected)
			}
			if _, err := LoadEnablement(path, expected); err == nil {
				t.Fatal("unsafe enablement artifact was accepted")
			}
		})
	}
}

func enablementExpected(raw []byte) EnablementExpected {
	return EnablementExpected{
		ArtifactDigest: digest.SHA256(raw), ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		IntentRevision: enablementSHA("1"), EnablementRevision: enablementSHA("2"), ExecutionFixture: enablementSHA("3"),
		ManagementAuthority: "ok-mgmt", ObjectIdentity: projection.ResourceIdentity{
			APIVersion: "addons.cluster.x-k8s.io/v1alpha1", Kind: "HelmChartProxy", Namespace: "disposable-ok147", Name: "disposable-ok147-cilium",
		},
	}
}

func enablementYAML() []byte {
	return []byte(`apiVersion: addons.cluster.x-k8s.io/v1alpha1
kind: HelmChartProxy
metadata:
  name: disposable-ok147-cilium
  namespace: disposable-ok147
  annotations:
    openkubes.io/contract-name: disposable-ok147
    openkubes.io/contract-namespace: disposable-ok147
    openkubes.io/intent-revision: ` + enablementSHA("1") + `
    openkubes.io/enablement-revision: ` + enablementSHA("2") + `
    openkubes.io/execution-fixture: ` + enablementSHA("3") + `
    openkubes.io/oci-manifest-digest: ` + enablementSHA("4") + `
    openkubes.io/chart-artifact-digest: ` + enablementSHA("5") + `
    openkubes.io/values-digest: ` + enablementSHA("6") + `
    openkubes.io/digest-enforcement: external-evidence-required
spec:
  clusterSelector:
    matchLabels:
      openkubes.io/type: talos
      openkubes.io/provider: kubevirt
  chartName: cilium
  repoURL: oci://quay.io/cilium/charts
  releaseName: cilium
  namespace: kube-system
  version: 1.19.6
  reconcileStrategy: Continuous
  valuesTemplate: |
    operator:
      replicas: 1
  options:
    atomic: true
    wait: true
    waitForJobs: true
`)
}

func writeEnablement(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enablement.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func enablementSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
