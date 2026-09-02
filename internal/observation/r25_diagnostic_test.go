package observation

import (
	"context"
	"testing"
)

func TestR25ReconstructedCAAPHPartialConditionsRemainPollable(t *testing.T) {
	policy, profile, management, workload, probe := collectorFixture(t)
	collector := mustNetworkCollector(t, policy, management, workload, probe)

	hcpPath, hrpPath := managementNetworkPaths("disposable-ok141", "disposable-ok141", "disposable-ok141-cilium")
	management.responses[hcpPath] = mutateJSON(t, management.responses[hcpPath], func(value map[string]any) {
		status := value["status"].(map[string]any)
		conditions := status["conditions"].([]any)
		for _, condition := range conditions {
			candidate := condition.(map[string]any)
			if candidate["type"] == "HelmReleaseProxySpecsUpToDate" {
				status["conditions"] = []any{candidate}
				return
			}
		}
		t.Fatal("fixture lacks HCP specs condition")
	})
	management.responses[hrpPath] = mutateJSON(t, management.responses[hrpPath], func(value map[string]any) {
		item := value["items"].([]any)[0].(map[string]any)
		status := item["status"].(map[string]any)
		status["conditions"] = []any{map[string]any{
			"type": "ClusterAvailable", "status": "True", "observedGeneration": float64(1),
		}}
	})

	evidence, err := collector.Observe(context.Background(), policy, profile)
	if err != nil {
		t.Fatalf("reconstructed R25 partial CAAPH shape failed: %v", err)
	}
	if evidence.Status != "Unknown" {
		t.Fatalf("partial CAAPH shape must remain pollable, got %q", evidence.Status)
	}
}
