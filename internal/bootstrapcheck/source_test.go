package bootstrapcheck

import (
	"encoding/json"
	"strings"
	"testing"
)

func sourceFixture() string {
	return `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"namespace":"fixture","name":"fixture-ca","uid":"fixture-secret-uid","resourceVersion":"123","creationTimestamp":"2026-10-18T12:00:00Z","deletionTimestamp":null,"ownerReferences":[{"apiVersion":"cluster.x-k8s.io/v1beta1","kind":"Cluster","name":"fixture-cluster","uid":"fixture-target-uid","controller":true,"blockOwnerDeletion":true}]}}`
}

func TestSourceMetadataMatchesIndependentIdentity(t *testing.T) {
	f := newFixture(t)
	owner := SourceOwner{"cluster.x-k8s.io/v1beta1", "fixture-cluster"}
	if err := ValidateSourceMetadata([]byte(sourceFixture()), f.r.Binding, owner); err != nil {
		t.Fatal(err)
	}
	owner.APIVersion = "cluster.x-k8s.io/v1beta2"
	if err := ValidateSourceMetadata([]byte(strings.ReplaceAll(sourceFixture(), "cluster.x-k8s.io/v1beta1", owner.APIVersion)), f.r.Binding, owner); err != nil {
		t.Fatal(err)
	}
}

func TestSourceMetadataRejectsDriftAndFullObjects(t *testing.T) {
	cases := map[string]string{
		"namespace":            strings.Replace(sourceFixture(), `"namespace":"fixture"`, `"namespace":"other"`, 1),
		"name":                 strings.Replace(sourceFixture(), `"name":"fixture-ca"`, `"name":"other"`, 1),
		"recreated UID":        strings.Replace(sourceFixture(), "fixture-secret-uid", "recreated-secret-uid", 1),
		"resourceVersion":      strings.Replace(sourceFixture(), `"resourceVersion":"123"`, `"resourceVersion":"124"`, 1),
		"owner UID":            strings.Replace(sourceFixture(), "fixture-target-uid", "other-target-uid", 1),
		"owner name":           strings.Replace(sourceFixture(), "fixture-cluster", "other-cluster", 1),
		"owner kind":           strings.Replace(sourceFixture(), `"kind":"Cluster"`, `"kind":"Machine"`, 1),
		"owner group":          strings.Replace(sourceFixture(), "cluster.x-k8s.io/v1beta1", "other.io/v1beta1", 1),
		"not controller":       strings.Replace(sourceFixture(), `"controller":true`, `"controller":false`, 1),
		"deleting":             strings.Replace(sourceFixture(), `"deletionTimestamp":null`, `"deletionTimestamp":"2026-10-18T12:01:00Z"`, 1),
		"duplicate UID":        strings.Replace(sourceFixture(), `"uid":"fixture-secret-uid"`, `"uid":"other","uid":"fixture-secret-uid"`, 1),
		"case alias UID":       strings.Replace(sourceFixture(), `"uid":"fixture-secret-uid"`, `"uid":"other","UID":"fixture-secret-uid"`, 1),
		"case alias owner":     strings.Replace(sourceFixture(), `"uid":"fixture-target-uid"`, `"uid":"other","UID":"fixture-target-uid"`, 1),
		"case alias kind":      strings.Replace(sourceFixture(), `"kind":"PartialObjectMetadata"`, `"kind":"Secret","KIND":"PartialObjectMetadata"`, 1),
		"trailing object":      sourceFixture() + `{}`,
		"full Secret":          strings.Replace(strings.Replace(sourceFixture(), `"apiVersion":"meta.k8s.io/v1"`, `"apiVersion":"v1"`, 1), `"kind":"PartialObjectMetadata"`, `"kind":"Secret"`, 1),
		"disguised data":       strings.Replace(sourceFixture(), `"metadata":`, `"data":{"tls.key":"SENSITIVE_FIXTURE"},"metadata":`, 1),
		"disguised stringData": strings.Replace(sourceFixture(), `"metadata":`, `"stringData":{"tls.key":"SENSITIVE_FIXTURE"},"metadata":`, 1),
		"list":                 `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadataList","items":[]}`,
		"null":                 `null`,
		"oversized":            strings.Repeat(" ", 256*1024+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			err := ValidateSourceMetadata([]byte(raw), f.r.Binding, SourceOwner{"cluster.x-k8s.io/v1beta1", "fixture-cluster"})
			if err == nil {
				t.Fatal("accepted invalid source metadata")
			}
			if strings.Contains(err.Error(), "SENSITIVE_FIXTURE") {
				t.Fatal("error disclosed input")
			}
		})
	}
}

func TestSourceMetadataOwnerAmbiguityAndMissingExpectations(t *testing.T) {
	f := newFixture(t)
	var doc map[string]any
	if err := json.Unmarshal([]byte(sourceFixture()), &doc); err != nil {
		t.Fatal(err)
	}
	metadata := doc["metadata"].(map[string]any)
	owners := metadata["ownerReferences"].([]any)
	for _, refs := range [][]any{nil, {}, {owners[0], owners[0]}} {
		metadata["ownerReferences"] = refs
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if ValidateSourceMetadata(raw, f.r.Binding, SourceOwner{"cluster.x-k8s.io/v1beta1", "fixture-cluster"}) == nil {
			t.Fatal("accepted absent/ambiguous owner")
		}
	}
	if ValidateSourceMetadata([]byte(sourceFixture()), f.r.Binding, SourceOwner{}) == nil {
		t.Fatal("accepted missing owner expectation")
	}
	f.r.Binding.SourceUID = ""
	if ValidateSourceMetadata([]byte(sourceFixture()), f.r.Binding, SourceOwner{"cluster.x-k8s.io/v1beta1", "fixture-cluster"}) == nil {
		t.Fatal("accepted missing source UID")
	}
}
