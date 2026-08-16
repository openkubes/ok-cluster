// Package executor defines the immutable request passed between validation,
// authorization, and a future bounded submitter.
package executor

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
)

const RequestFormat = "ok147-create-request/v1"

// CreateRequest contains semantic intent and verified projection identities.
// It contains no credentials, paths, commands, or Kubernetes client options.
type CreateRequest struct {
	Format                  string             `json:"format"`
	Operation               string             `json:"operation"`
	ContractIdentity        contract.Identity  `json:"contractIdentity"`
	ContractRevision        string             `json:"contractRevision"`
	CanonicalizationProfile string             `json:"canonicalizationProfile"`
	RawArtifactDigest       string             `json:"rawArtifactDigest"`
	SchemaDigest            string             `json:"schemaDigest"`
	Projection              projection.Binding `json:"projection"`
}

// NewCreateRequest binds a canonical contract to an independently rendered and
// verified projection.
func NewCreateRequest(result contract.Result, identity contract.Identity, binding projection.Binding) (CreateRequest, error) {
	if binding.IntentRevision != result.NormalizedDigest {
		return CreateRequest{}, fmt.Errorf("projection revision %s differs from contract revision %s", binding.IntentRevision, result.NormalizedDigest)
	}
	if binding.ContractIdentity != identity {
		return CreateRequest{}, fmt.Errorf("projection identity differs from contract identity")
	}
	return CreateRequest{
		Format:                  RequestFormat,
		Operation:               "CreateCluster",
		ContractIdentity:        identity,
		ContractRevision:        result.NormalizedDigest,
		CanonicalizationProfile: result.CanonicalizationProfile,
		RawArtifactDigest:       result.RawArtifactDigest,
		SchemaDigest:            result.SchemaDigest,
		Projection:              binding,
	}, nil
}

// Digest returns the canonical semantic identity of a request.
func Digest(request CreateRequest) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}
