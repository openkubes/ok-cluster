package executor

import (
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/projection"
)

func TestDigestIsDeterministicAndBindsProjection(t *testing.T) {
	identity := contract.Identity{Name: "disposable-ok141", Namespace: "disposable-ok141"}
	request := CreateRequest{
		Format: RequestFormat, Operation: "CreateCluster", ContractIdentity: identity,
		ContractRevision: "sha256:" + strings.Repeat("1", 64),
		Projection:       projection.Binding{Format: projection.BindingFormat, IntentRevision: "sha256:" + strings.Repeat("1", 64), ContractIdentity: identity, ManifestDigest: "sha256:" + strings.Repeat("2", 64)},
	}
	first, err := Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest(request)
	if err != nil || first != second {
		t.Fatalf("digest is not deterministic: %s %s %v", first, second, err)
	}
	request.Projection.ManifestDigest = "sha256:" + strings.Repeat("3", 64)
	changed, err := Digest(request)
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatal("projection change did not alter request digest")
	}
}
