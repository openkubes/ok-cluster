package contract

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const ok141Revision = "sha256:166504ae61fd558d391daedde50986cbc7a28f5f4e9d57f4acbd0433b448aa0f"

func fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/ok141-contract-v5.yaml")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("testdata/ok141-contract-v3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw, schema
}

func TestCanonicalizeReproducesOK141Revision(t *testing.T) {
	raw, schema := fixture(t)
	result, err := Canonicalize(raw, schema)
	if err != nil {
		t.Fatal(err)
	}
	if result.NormalizedDigest != ok141Revision {
		t.Fatalf("revision = %s, want %s", result.NormalizedDigest, ok141Revision)
	}
	identity, err := ContractIdentity(result.Normalized)
	if err != nil {
		t.Fatal(err)
	}
	if identity != (Identity{Name: "disposable-ok141", Namespace: "disposable-ok141"}) {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestEquivalentContractHasSameSemanticRevision(t *testing.T) {
	raw, schema := fixture(t)
	original, err := Canonicalize(raw, schema)
	if err != nil {
		t.Fatal(err)
	}
	equivalent := bytes.Replace(raw,
		[]byte("  namespace: disposable-ok141\n"),
		[]byte("  namespace: disposable-ok141\n  uid: historical-runtime-uid\n  generation: 7\n"), 1)
	equivalent = append(equivalent, []byte("status: {}\n")...)
	changed, err := Canonicalize(equivalent, schema)
	if err != nil {
		t.Fatal(err)
	}
	if !EqualNormalized(original, changed) {
		t.Fatalf("equivalent contracts differ: %s != %s", original.NormalizedDigest, changed.NormalizedDigest)
	}
	if original.RawArtifactDigest == changed.RawArtifactDigest {
		t.Fatal("raw artifact digest did not change")
	}
}

func TestSemanticChangeChangesRevision(t *testing.T) {
	raw, schema := fixture(t)
	original, err := Canonicalize(raw, schema)
	if err != nil {
		t.Fatal(err)
	}
	changedRaw := bytes.Replace(raw, []byte("v1.36.2"), []byte("v1.36.3"), 1)
	changed, err := Canonicalize(changedRaw, schema)
	if err != nil {
		t.Fatal(err)
	}
	if original.NormalizedDigest == changed.NormalizedDigest {
		t.Fatal("semantic change retained the same revision")
	}
}

func TestUnknownAndDuplicateFieldsFailClosed(t *testing.T) {
	raw, schema := fixture(t)
	cases := map[string][]byte{
		"unknown":   append(append([]byte{}, raw...), []byte("unexpected: true\n")...),
		"duplicate": append(append([]byte{}, raw...), []byte("kind: ClusterIntentFixture\n")...),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Canonicalize(candidate, schema); err == nil {
				t.Fatal("invalid contract was accepted")
			}
		})
	}
}

func TestCIDRPolicyFailsClosed(t *testing.T) {
	raw, schema := fixture(t)
	overlap := bytes.Replace(raw, []byte("serviceCIDR: 10.100.0.0/20"), []byte("serviceCIDR: 10.40.0.0/20"), 1)
	if _, err := Canonicalize(overlap, schema); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("overlap error = %v", err)
	}
	nonCanonical := bytes.Replace(raw, []byte("podCIDR: 10.40.0.0/16"), []byte("podCIDR: 10.40.1.0/16"), 1)
	if _, err := Canonicalize(nonCanonical, schema); err == nil || !strings.Contains(err.Error(), "canonical IPv4 CIDR") {
		t.Fatalf("non-canonical error = %v", err)
	}
}

func TestSchemaDefaultIsAppliedBeforeHashing(t *testing.T) {
	raw, schema := fixture(t)
	withoutForbidden := bytes.Replace(raw, []byte("    forbiddenCIDRs: [192.168.100.0/24]\n"), nil, 1)
	result, err := Canonicalize(withoutForbidden, schema)
	if err != nil {
		t.Fatal(err)
	}
	root := result.Normalized.(map[string]any)
	spec := root["spec"].(map[string]any)
	connectivity := spec["connectivity"].(map[string]any)
	forbidden := connectivity["forbiddenCIDRs"].([]any)
	if len(forbidden) != 0 {
		t.Fatalf("default forbiddenCIDRs = %#v", forbidden)
	}
}

func TestFloatAndYAMLAliasAreRejected(t *testing.T) {
	raw, schema := fixture(t)
	floating := bytes.Replace(raw, []byte("cores: 2"), []byte("cores: 2.5"), 1)
	if _, err := Canonicalize(floating, schema); err == nil {
		t.Fatal("floating-point contract was accepted")
	}
	alias := bytes.Replace(raw,
		[]byte("metadata:\n  name: disposable-ok141"),
		[]byte("metadata: &metadata\n  name: disposable-ok141"), 1)
	alias = append(alias, []byte("status: *metadata\n")...)
	if _, err := Canonicalize(alias, schema); err == nil || !strings.Contains(err.Error(), "aliases are not allowed") {
		t.Fatalf("alias error = %v", err)
	}
}
