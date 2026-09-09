package dryrun

import (
	"encoding/json"
	"net/http"

	"github.com/openkubes/ok-cluster/internal/contract"
)

type Handler struct{ Schema []byte }

type request struct {
	Contract map[string]any `json:"contract"`
	DryRun   bool           `json:"dryRun"`
}

type response struct {
	Format           string `json:"format"`
	Operation        string `json:"operation"`
	ContractIdentity string `json:"contractIdentity"`
	ContractRevision string `json:"contractRevision"`
	MutationAllowed  bool   `json:"mutationAllowed"`
	Canonicalization string `json:"canonicalizationProfile"`
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(h.Schema) == 0 {
		http.Error(w, "dry-run schema is not configured", http.StatusServiceUnavailable)
		return
	}
	var input request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	if err := decoder.Decode(&input); err != nil || !input.DryRun || input.Contract == nil {
		http.Error(w, "a dry-run contract is required", http.StatusBadRequest)
		return
	}
	raw, err := json.Marshal(input.Contract)
	if err != nil {
		http.Error(w, "invalid contract", http.StatusBadRequest)
		return
	}
	result, err := contract.Canonicalize(raw, h.Schema)
	if err != nil {
		http.Error(w, "contract validation failed", http.StatusBadRequest)
		return
	}
	identity, err := contract.ContractIdentity(result.Normalized)
	if err != nil {
		http.Error(w, "contract identity is invalid", http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(response{Format: "ok147-create-plan/v1", Operation: "CreateCluster", ContractIdentity: identity.Namespace + "/" + identity.Name, ContractRevision: result.NormalizedDigest, MutationAllowed: false, Canonicalization: result.CanonicalizationProfile})
}
