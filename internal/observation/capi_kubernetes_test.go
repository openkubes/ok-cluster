package observation

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestCAPILifecycleObserverCollectsCurrentExactEvidence(t *testing.T) {
	policy := testPolicy(t)
	requests := 0
	client := &http.Client{Transport: capiRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/apis/cluster.x-k8s.io/v1beta2/namespaces/disposable-ok141/clusters/disposable-ok141" || request.URL.RawQuery != "" {
			t.Errorf("unbounded request: %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer observer-token" {
			t.Error("missing bounded observer credential")
		}
		return capiJSONResponse(t, http.StatusOK, capiFixture(policy, policy.TargetClusterUID, policy.IntentRevision, 7, 7)), nil
	})}

	observer := newTestCAPIObserver(t, client)
	evidence, err := observer.Collect(context.Background(), policy)
	if err != nil || requests != 1 || len(evidence) != 2 {
		t.Fatalf("collect evidence: count=%d requests=%d err=%v", len(evidence), requests, err)
	}
	for _, item := range evidence {
		if item.Source != "CAPICluster" || item.SourceUID != policy.TargetClusterUID || item.TargetClusterUID != policy.TargetClusterUID || item.Generation != 7 || item.ObservedGeneration != 7 || !validDigest(item.EvidenceDigest) {
			t.Fatalf("unexpected CAPI evidence: %#v", item)
		}
	}

	bundle := completeBundle(policy)
	bundle.Evidence[0], bundle.Evidence[1] = evidence[0], evidence[1]
	result, err := Evaluate(policy, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "True" {
		t.Fatalf("current authoritative evidence did not converge: %#v", receipt)
	}
}

func TestCAPILifecycleObserverBindsExactRuntimeIdentityAfterRestart(t *testing.T) {
	policy := testPolicy(t)
	policy.TargetClusterUID = ""
	const runtimeUID = "cluster-runtime-uid-147"
	client := &http.Client{Transport: capiRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return capiJSONResponse(t, http.StatusOK, capiFixture(policy, runtimeUID, policy.IntentRevision, 7, 7)), nil
	})}
	bound, evidence, err := newTestCAPIObserver(t, client).CollectBound(context.Background(), policy, digest.SHA256([]byte(runtimeUID)))
	if err != nil {
		t.Fatal(err)
	}
	if bound.TargetClusterUID != runtimeUID || len(evidence) != 2 || evidence[0].SourceUID != runtimeUID || evidence[0].TargetClusterUID != runtimeUID {
		t.Fatalf("runtime correlation differs: %#v %#v", bound, evidence)
	}
}

func TestCAPILifecycleObserverRejectsChangedRuntimeIdentityAfterRestart(t *testing.T) {
	policy := testPolicy(t)
	policy.TargetClusterUID = ""
	client := &http.Client{Transport: capiRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return capiJSONResponse(t, http.StatusOK, capiFixture(policy, "replacement-cluster-uid", policy.IntentRevision, 7, 7)), nil
	})}
	if _, _, err := newTestCAPIObserver(t, client).CollectBound(context.Background(), policy, digest.SHA256([]byte("original-cluster-uid"))); err == nil {
		t.Fatal("replacement Cluster with the same name and revision was accepted")
	}
	policy.TargetClusterUID = "caller-selected-uid"
	if _, _, err := newTestCAPIObserver(t, client).CollectBound(context.Background(), policy, digest.SHA256([]byte("caller-selected-uid"))); err == nil {
		t.Fatal("caller-selected target UID was accepted at resume boundary")
	}
}

func TestCAPILifecycleObserverPreservesFailClosedCorrelation(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate func(Policy) map[string]any
		reason string
	}{
		"missing revision": {
			mutate: func(policy Policy) map[string]any { return capiFixture(policy, policy.TargetClusterUID, "", 7, 7) },
			reason: "RevisionCorrelationUnproven",
		},
		"foreign uid": {
			mutate: func(policy Policy) map[string]any {
				return capiFixture(policy, "foreign-cluster-uid", policy.IntentRevision, 7, 7)
			},
			reason: "RevisionCorrelationUnproven",
		},
		"stale generation": {
			mutate: func(policy Policy) map[string]any {
				return capiFixture(policy, policy.TargetClusterUID, policy.IntentRevision, 8, 7)
			},
			reason: "SourceObservationStale",
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy(t)
			client := &http.Client{Transport: capiRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return capiJSONResponse(t, http.StatusOK, testCase.mutate(policy)), nil
			})}
			observer := newTestCAPIObserver(t, client)
			evidence, err := observer.Collect(context.Background(), policy)
			if err != nil {
				t.Fatal(err)
			}
			bundle := completeBundle(policy)
			bundle.Evidence[0], bundle.Evidence[1] = evidence[0], evidence[1]
			result, err := Evaluate(policy, bundle)
			if err != nil {
				t.Fatal(err)
			}
			receipt, _ := result.Receipt()
			if receipt.Ready != "Unknown" || receipt.Reason != testCase.reason {
				t.Fatalf("unsafe correlation result: %#v", receipt)
			}
		})
	}
}

func TestCAPILifecycleObserverRejectsAmbiguousOrForeignObjects(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"duplicate condition": func(cluster map[string]any) {
			status := cluster["status"].(map[string]any)
			conditions := status["conditions"].([]map[string]any)
			status["conditions"] = append(conditions, conditions[0])
		},
		"wrong name": func(cluster map[string]any) {
			cluster["metadata"].(map[string]any)["name"] = "other"
		},
		"missing runtime identity": func(cluster map[string]any) {
			cluster["metadata"].(map[string]any)["resourceVersion"] = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy(t)
			cluster := capiFixture(policy, policy.TargetClusterUID, policy.IntentRevision, 7, 7)
			mutate(cluster)
			client := &http.Client{Transport: capiRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return capiJSONResponse(t, http.StatusOK, cluster), nil
			})}
			observer := newTestCAPIObserver(t, client)
			if _, err := observer.Collect(context.Background(), policy); err == nil {
				t.Fatal("ambiguous or foreign CAPI object accepted")
			}
		})
	}
}

func TestCAPILifecycleObserverNormalizesInvalidReasonAndMissingCondition(t *testing.T) {
	policy := testPolicy(t)
	cluster := capiFixture(policy, policy.TargetClusterUID, policy.IntentRevision, 7, 7)
	status := cluster["status"].(map[string]any)
	conditions := status["conditions"].([]map[string]any)
	conditions[0]["reason"] = "invalid reason with spaces"
	status["conditions"] = conditions[:1]
	client := &http.Client{Transport: capiRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return capiJSONResponse(t, http.StatusOK, cluster), nil
	})}

	evidence, err := newTestCAPIObserver(t, client).Collect(context.Background(), policy)
	if err != nil || len(evidence) != 1 || evidence[0].Reason != "SourceReasonUnavailable" {
		t.Fatalf("unexpected normalized evidence: %#v %v", evidence, err)
	}
	bundle := completeBundle(policy)
	bundle.Evidence = append(evidence, bundle.Evidence[2:]...)
	result, err := Evaluate(policy, bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := result.Receipt()
	if receipt.Ready != "Unknown" || receipt.Reason != "RequiredEvidenceMissing" {
		t.Fatalf("missing condition did not fail closed: %#v", receipt)
	}
}

func newTestCAPIObserver(t *testing.T, client *http.Client) *CAPILifecycleObserver {
	t.Helper()
	observer, err := NewCAPILifecycleObserver(CAPILifecycleObserverConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "observer-token", Namespace: "disposable-ok141",
		Name: "disposable-ok141", Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return observer
}

func capiFixture(policy Policy, uid, revision string, generation, observedGeneration int64) map[string]any {
	annotations := map[string]string{}
	if revision != "" {
		annotations[intentRevisionKey] = revision
	}
	return map[string]any{
		"apiVersion": capiClusterAPIVersion,
		"kind":       capiClusterKind,
		"metadata": map[string]any{
			"name": "disposable-ok141", "namespace": "disposable-ok141", "uid": uid,
			"resourceVersion": "41", "generation": generation, "annotations": annotations,
		},
		"spec": map[string]any{"paused": false},
		"status": map[string]any{"conditions": []map[string]any{
			{"type": "InfrastructureReady", "status": "True", "reason": "InfrastructureReady", "message": "redacted by observer", "observedGeneration": observedGeneration},
			{"type": "ControlPlaneAvailable", "status": "True", "reason": "ControlPlaneAvailable", "observedGeneration": observedGeneration},
		}},
	}
}

type capiRoundTripFunc func(*http.Request) (*http.Response, error)

func (function capiRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func capiJSONResponse(t *testing.T, status int, cluster map[string]any) *http.Response {
	t.Helper()
	var buffer bytes.Buffer
	if err := json.NewEncoder(&buffer).Encode(cluster); err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(buffer.Bytes())),
	}
}
