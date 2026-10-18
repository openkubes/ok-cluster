package stageauthority

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
)

// Reproduce externally supplied policies without going through FromPlan's
// recovery guard. The signer, not the policy generator, is the security seam.
func TestSignerRejectsExternalStageSevenPoliciesBeforeClaimOrSignature(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, subset := range []bool{false, true} {
			t.Run(version+map[bool]string{false: "/full-policy", true: "/legacy-recovery-policy"}[subset], func(t *testing.T) {
				plan := verifiedPlan(t)
				if version == "v2" {
					plan = verifiedPlanV2(t, testDigest("5"))
				}
				material := testMaterialForPlan(t, plan)
				raw, err := os.ReadFile(material.config.PolicyPath)
				if err != nil {
					t.Fatal(err)
				}
				var policy Policy
				if err := json.Unmarshal(raw, &policy); err != nil {
					t.Fatal(err)
				}
				stage, stageDigest, err := plan.Stage("target-access")
				if err != nil {
					t.Fatal(err)
				}
				if subset {
					policy.Stages = []StagePolicy{{StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest, Operation: stage.GrantOperation, Authority: stage.Authority, Requires: stage.Requires}}
				}
				// A caller can supply this policy and its matching digest. No
				// provenance distinguishes it from the old recovery-derived policy.
				raw, err = canonicalJSON(policy)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(material.config.PolicyPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				material.config.ExpectedPolicyDigest = digest.SHA256(raw)
				authority, _, err := Open(material.config)
				if err != nil {
					t.Fatal(err)
				}
				request := material.request
				request.StageID, request.StageOrder, request.StageDigest = stage.ID, stage.Order, stageDigest
				request.Operation, request.Authority = stage.GrantOperation, stage.Authority
				request.Predecessors = []stagecursor.Predecessor{{StageID: "runtime-binding", ReceiptDigest: testDigest("a")}}
				request.RequestDigest = stageRequestDigest(t, request)
				requestRaw := requestBytes(t, request)
				var wg sync.WaitGroup
				for i := 0; i < 16; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						response := performRequest(authority, material.token, requestMediaType, requestRaw)
						if response.Code != http.StatusForbidden {
							t.Errorf("unsupported signing returned %d: %s", response.Code, response.Body.String())
						}
						var signed struct {
							Signature json.RawMessage `json:"signature"`
						}
						_ = json.Unmarshal(response.Body.Bytes(), &signed)
						if len(signed.Signature) != 0 {
							t.Error("denied signing returned a signature")
						}
					}()
				}
				wg.Wait()
				entries, err := os.ReadDir(material.stateDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("denied signing consumed state: %v %v", entries, err)
				}
				t.Log("16 concurrent/repeated requests: HTTP 403, signatures=0, claims=0")
				// Normal supported Stage-1 signing stays separately covered by
				// TestAuthorityIssuesOneExactVerifiableGrant and the v2 counterpart.
			})
		}
	}
}
