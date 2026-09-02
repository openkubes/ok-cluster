package observation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNetworkSourceCollectorUsesOnlyBoundedSources(t *testing.T) {
	policy, profile, management, workload, probe := collectorFixture(t)
	collector, err := NewNetworkSourceCollector(management, workload, probe, NetworkCollectorConfig{
		Namespace: "disposable-ok141", Name: "disposable-ok141", HCPName: "disposable-ok141-cilium", TargetClusterUID: policy.TargetClusterUID,
		Clock: func() time.Time { return time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := collector.Observe(context.Background(), policy, profile)
	if err != nil || evidence.Status != "True" || evidence.Reason != "NetworkReady" {
		t.Fatalf("unexpected collected evidence: %#v %v", evidence, err)
	}
	wantManagement := []string{
		"/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmchartproxies/disposable-ok141-cilium",
		"/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmreleaseproxies?labelSelector=cluster.x-k8s.io%2Fcluster-name%3Ddisposable-ok141%2Chelmreleaseproxy.addons.cluster.x-k8s.io%2Fhelmchartproxy-name%3Ddisposable-ok141-cilium",
	}
	wantWorkload := []string{
		"/api/v1/nodes",
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium",
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium-envoy",
		"/apis/apps/v1/namespaces/kube-system/deployments/cilium-operator",
		"/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium",
	}
	if !reflect.DeepEqual(management.requests, wantManagement) || !reflect.DeepEqual(workload.requests, wantWorkload) {
		t.Fatalf("collector query boundary differs:\nmanagement=%#v\nworkload=%#v", management.requests, workload.requests)
	}
	if probe.calls != 1 || probe.podName != "cilium-a" || probe.podUID != "pod-uid-1" {
		t.Fatalf("fixed probe boundary differs: %#v", probe)
	}
}

func TestNetworkSourceCollectorNormalizesOrderDeterministically(t *testing.T) {
	policy, profile, management, workload, probe := collectorFixture(t)
	collector := mustNetworkCollector(t, policy, management, workload, probe)
	first, err := collector.Observe(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	reverseList(t, workload.responses["/api/v1/nodes"])
	reverseList(t, workload.responses["/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium"])
	reverseList(t, probe.response)
	second, err := collector.Observe(context.Background(), policy, profile)
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceDigest != second.EvidenceDigest || first.SourceUID != second.SourceUID {
		t.Fatalf("source ordering changed evidence identity: %#v %#v", first, second)
	}
}

func TestNetworkSourceCollectorNormalizesTransientConvergenceWithoutEarlyProbe(t *testing.T) {
	for name, mutate := range map[string]func(*fakeNetworkGetter, *fakeNetworkGetter){
		"HCP status not initialized": func(management, _ *fakeNetworkGetter) {
			management.responses[managementPathHCP] = mutateJSON(t, management.responses[managementPathHCP], func(value map[string]any) {
				delete(value, "status")
			})
		},
		"HRP not created": func(management, _ *fakeNetworkGetter) {
			management.responses[managementPathHRP] = mutateJSON(t, management.responses[managementPathHRP], func(value map[string]any) {
				value["items"] = []any{}
			})
		},
		"Node conditions not initialized": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter) {
			workload.responses["/api/v1/nodes"] = mutateJSON(t, workload.responses["/api/v1/nodes"], func(value map[string]any) {
				for _, item := range value["items"].([]any) {
					item.(map[string]any)["status"].(map[string]any)["conditions"] = []any{}
				}
			})
		},
		"Node Ready published before NetworkUnavailable": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter) {
			workload.responses["/api/v1/nodes"] = mutateJSON(t, workload.responses["/api/v1/nodes"], func(value map[string]any) {
				for _, item := range value["items"].([]any) {
					conditions := item.(map[string]any)["status"].(map[string]any)["conditions"].([]any)
					item.(map[string]any)["status"].(map[string]any)["conditions"] = conditions[:1]
				}
			})
		},
		"Node NetworkUnavailable published before Ready": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter) {
			workload.responses["/api/v1/nodes"] = mutateJSON(t, workload.responses["/api/v1/nodes"], func(value map[string]any) {
				for _, item := range value["items"].([]any) {
					conditions := item.(map[string]any)["status"].(map[string]any)["conditions"].([]any)
					item.(map[string]any)["status"].(map[string]any)["conditions"] = conditions[1:]
				}
			})
		},
		"Cilium Pods not created": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter) {
			workload.responses["/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium"] = mutateJSON(t, workload.responses["/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium"], func(value map[string]any) {
				value["items"] = []any{}
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy, profile, management, workload, probe := collectorFixture(t)
			mutate(management, workload)
			collector := mustNetworkCollector(t, policy, management, workload, probe)
			evidence, err := collector.Observe(context.Background(), policy, profile)
			if err != nil || evidence.Status != "Unknown" {
				t.Fatalf("transient convergence was not normalized to Unknown: evidence=%#v err=%v", evidence, err)
			}
			if probe.calls != 0 {
				t.Fatalf("functional probe ran before prerequisites converged: calls=%d", probe.calls)
			}
		})
	}
}

func TestAddonSpecDigestNormalizesCAAPHDefaultedFalse(t *testing.T) {
	requested := map[string]any{
		"chartName": "cilium", "repoURL": "oci://quay.io/cilium/charts", "version": "1.19.6",
		"releaseName": "cilium", "namespace": "kube-system", "reconcileStrategy": "Continuous",
		"valuesTemplate": "pinned-values", "options": map[string]any{"wait": true},
	}
	defaulted := map[string]any{}
	for key, value := range requested {
		defaulted[key] = value
	}
	defaulted["options"] = map[string]any{"wait": true, "enableClientCache": false}
	want, err := addonSpecDigest(requested, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := addonSpecDigest(defaulted, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("CAAPH false default changed HCP semantics: got %s want %s", got, want)
	}
	defaulted["options"] = map[string]any{"wait": true, "enableClientCache": true}
	changed, err := addonSpecDigest(defaulted, false)
	if err != nil {
		t.Fatal(err)
	}
	if changed == want {
		t.Fatal("explicit enableClientCache=true did not change HCP semantics")
	}
}

func TestNetworkSourceCollectorRejectsDifferentRuntimeAuthorityBeforeReads(t *testing.T) {
	policy, _, management, workload, probe := collectorFixture(t)
	collector := mustNetworkCollector(t, policy, management, workload, probe)
	policy.TargetClusterUID = "different-runtime-cluster-uid"
	if _, err := collector.Collect(context.Background(), policy); err == nil {
		t.Fatal("collector accepted a policy for a different runtime authority")
	}
	if len(management.requests) != 0 || len(workload.requests) != 0 || probe.calls != 0 {
		t.Fatal("authority mismatch reached a network source")
	}
}

func TestNetworkSourceCollectorFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*fakeNetworkGetter, *fakeNetworkGetter, *fakeFixedProbe){
		"foreign HCP": func(management, _ *fakeNetworkGetter, _ *fakeFixedProbe) {
			management.responses[managementPathHCP] = mutateJSON(t, management.responses[managementPathHCP], func(value map[string]any) {
				value["metadata"].(map[string]any)["name"] = "other"
			})
		},
		"duplicated Node condition": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter, _ *fakeFixedProbe) {
			workload.responses["/api/v1/nodes"] = mutateJSON(t, workload.responses["/api/v1/nodes"], func(value map[string]any) {
				node := value["items"].([]any)[0].(map[string]any)
				conditions := node["status"].(map[string]any)["conditions"].([]any)
				node["status"].(map[string]any)["conditions"] = append(conditions, conditions[0])
			})
		},
		"malformed HCP matchingClusters": func(management, _ *fakeNetworkGetter, _ *fakeFixedProbe) {
			management.responses[managementPathHCP] = mutateJSON(t, management.responses[managementPathHCP], func(value map[string]any) {
				value["status"].(map[string]any)["matchingClusters"] = "invalid"
			})
		},
		"malformed Cilium containerStatuses": func(_ *fakeNetworkGetter, workload *fakeNetworkGetter, _ *fakeFixedProbe) {
			path := "/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium"
			workload.responses[path] = mutateJSON(t, workload.responses[path], func(value map[string]any) {
				value["items"].([]any)[0].(map[string]any)["status"].(map[string]any)["containerStatuses"] = "invalid"
			})
		},
		"foreign probe Node": func(_ *fakeNetworkGetter, _ *fakeNetworkGetter, probe *fakeFixedProbe) {
			probe.response = mutateJSON(t, probe.response, func(value map[string]any) {
				value["nodes"].([]any)[0].(map[string]any)["name"] = "foreign"
			})
		},
		"invalid probe status representation": func(_ *fakeNetworkGetter, _ *fakeNetworkGetter, probe *fakeFixedProbe) {
			probe.response = mutateJSON(t, probe.response, func(value map[string]any) {
				node := value["nodes"].([]any)[0].(map[string]any)
				path := node["host"].(map[string]any)["primary-address"].(map[string]any)["http"].(map[string]any)
				path["status"] = nil
			})
		},
		"ambiguous HRP collection": func(management, _ *fakeNetworkGetter, _ *fakeFixedProbe) {
			path := "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmreleaseproxies?labelSelector=cluster.x-k8s.io%2Fcluster-name%3Ddisposable-ok141%2Chelmreleaseproxy.addons.cluster.x-k8s.io%2Fhelmchartproxy-name%3Ddisposable-ok141-cilium"
			management.responses[path] = mutateJSON(t, management.responses[path], func(value map[string]any) {
				value["items"] = append(value["items"].([]any), "malformed")
			})
		},
		"trailing probe JSON": func(_ *fakeNetworkGetter, _ *fakeNetworkGetter, probe *fakeFixedProbe) {
			probe.response = append(probe.response, []byte(` {"unexpected":true}`)...)
		},
		"source transport error": func(management, _ *fakeNetworkGetter, _ *fakeFixedProbe) {
			management.errors = map[string]error{managementPathHCP: errors.New("https://sensitive-endpoint:6443/token")}
		},
		"probe execution error": func(_ *fakeNetworkGetter, _ *fakeNetworkGetter, probe *fakeFixedProbe) {
			probe.err = errors.New("sensitive raw failure")
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy, profile, management, workload, probe := collectorFixture(t)
			mutate(management, workload, probe)
			collector := mustNetworkCollector(t, policy, management, workload, probe)
			if _, err := collector.Observe(context.Background(), policy, profile); err == nil {
				t.Fatal("malformed or foreign network source accepted")
			} else if (name == "probe execution error" || name == "source transport error") && strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("raw source error leaked: %v", err)
			}
		})
	}
}

const managementPathHCP = "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmchartproxies/disposable-ok141-cilium"
const managementPathHRP = "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmreleaseproxies?labelSelector=cluster.x-k8s.io%2Fcluster-name%3Ddisposable-ok141%2Chelmreleaseproxy.addons.cluster.x-k8s.io%2Fhelmchartproxy-name%3Ddisposable-ok141-cilium"

type fakeNetworkGetter struct {
	responses map[string][]byte
	errors    map[string]error
	requests  []string
}

func (getter *fakeNetworkGetter) Get(_ context.Context, path string) ([]byte, error) {
	getter.requests = append(getter.requests, path)
	if err := getter.errors[path]; err != nil {
		return nil, err
	}
	raw, ok := getter.responses[path]
	if !ok {
		return nil, errors.New("unexpected bounded GET")
	}
	return append([]byte(nil), raw...), nil
}

type fakeFixedProbe struct {
	response []byte
	err      error
	calls    int
	podName  string
	podUID   string
}

func (probe *fakeFixedProbe) Probe(_ context.Context, name, uid string) ([]byte, error) {
	probe.calls++
	probe.podName, probe.podUID = name, uid
	return append([]byte(nil), probe.response...), probe.err
}

func collectorFixture(t *testing.T) (Policy, NetworkProfile, *fakeNetworkGetter, *fakeNetworkGetter, *fakeFixedProbe) {
	t.Helper()
	policy, profile, _ := validNetworkFixture(t)
	namespace, cluster, hcpName := "disposable-ok141", "disposable-ok141", "disposable-ok141-cilium"
	hcpSpec := map[string]any{
		"chartName": "cilium", "repoURL": "oci://quay.io/cilium/charts", "version": "1.19.6",
		"releaseName": "cilium", "namespace": "kube-system", "reconcileStrategy": "Continuous",
		"valuesTemplate": "pinned-values", "options": map[string]any{"wait": true},
	}
	hrpSpec := map[string]any{
		"chartName": "cilium", "repoURL": "oci://quay.io/cilium/charts", "version": "1.19.6",
		"releaseName": "cilium", "namespace": "kube-system", "reconcileStrategy": "Continuous", "values": "pinned-values",
		"clusterRef": map[string]any{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "namespace": namespace, "name": cluster},
	}
	profile.ExpectedHCPSpecDigest, _ = addonSpecDigest(hcpSpec, false)
	profile.ExpectedHRPSpecDigest, _ = addonSpecDigest(hrpSpec, true)
	condition := func(kind string) map[string]any {
		return map[string]any{"type": kind, "status": "True", "observedGeneration": 4}
	}
	hcp := map[string]any{
		"apiVersion": "addons.cluster.x-k8s.io/v1alpha1", "kind": "HelmChartProxy",
		"metadata": map[string]any{"name": hcpName, "namespace": namespace, "uid": "hcp-uid-1", "generation": 4,
			"annotations": map[string]any{"openkubes.io/intent-revision": policy.IntentRevision, "openkubes.io/enablement-revision": policy.EnablementRevision}},
		"spec": hcpSpec,
		"status": map[string]any{"observedGeneration": 4, "matchingClusters": []any{map[string]any{"namespace": namespace, "name": cluster}},
			"conditions": []any{condition("Ready"), condition("HelmReleaseProxySpecsUpToDate"), condition("HelmReleaseProxiesReady")}},
	}
	hrp := map[string]any{
		"apiVersion": "addons.cluster.x-k8s.io/v1alpha1", "kind": "HelmReleaseProxy",
		"metadata": map[string]any{"name": "cilium-disposable-ok141-a", "namespace": namespace, "uid": "hrp-uid-1", "generation": 4,
			"ownerReferences": []any{map[string]any{"kind": "HelmChartProxy", "name": hcpName, "uid": "hcp-uid-1", "controller": true}}},
		"spec": hrpSpec,
		"status": map[string]any{"observedGeneration": 4, "status": "deployed", "revision": 1,
			"conditions": []any{condition("Ready"), condition("HelmReleaseReady")}},
	}
	node := func(name, uid string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Node", "metadata": map[string]any{"name": name, "uid": uid},
			"spec": map[string]any{"providerID": "provider://" + name}, "status": map[string]any{"conditions": []any{
				map[string]any{"type": "Ready", "status": "True"}, map[string]any{"type": "NetworkUnavailable", "status": "False", "reason": "CiliumIsUp"},
			}}}
	}
	component := func(kind, name, uid, container, image string, desired int) map[string]any {
		status := map[string]any{"observedGeneration": 3, "desiredNumberScheduled": desired, "updatedNumberScheduled": desired, "numberAvailable": desired, "numberReady": desired}
		spec := map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": container, "image": image}}}}}
		if kind == "Deployment" {
			spec["replicas"] = desired
			status = map[string]any{"observedGeneration": 3, "updatedReplicas": desired, "availableReplicas": desired, "readyReplicas": desired}
		}
		return map[string]any{"apiVersion": "apps/v1", "kind": kind, "metadata": map[string]any{"name": name, "namespace": "kube-system", "uid": uid, "generation": 3}, "spec": spec, "status": status}
	}
	pod := func(name, uid, nodeName string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": "kube-system", "uid": uid},
			"spec": map[string]any{"nodeName": nodeName}, "status": map[string]any{"phase": "Running", "containerStatuses": []any{map[string]any{"name": "cilium-agent", "ready": true}}}}
	}
	management := &fakeNetworkGetter{responses: map[string][]byte{
		managementPathHCP: jsonBytes(t, hcp),
		"/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/disposable-ok141/helmreleaseproxies?labelSelector=cluster.x-k8s.io%2Fcluster-name%3Ddisposable-ok141%2Chelmreleaseproxy.addons.cluster.x-k8s.io%2Fhelmchartproxy-name%3Ddisposable-ok141-cilium": jsonBytes(t, map[string]any{"apiVersion": "addons.cluster.x-k8s.io/v1alpha1", "kind": "HelmReleaseProxyList", "items": []any{hrp}}),
	}}
	workload := &fakeNetworkGetter{responses: map[string][]byte{
		"/api/v1/nodes": jsonBytes(t, map[string]any{"apiVersion": "v1", "kind": "NodeList", "items": []any{node("node-b", "node-uid-2"), node("node-a", "node-uid-1")}}),
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium":             jsonBytes(t, component("DaemonSet", "cilium", "component-uid-1", "cilium-agent", profile.ExpectedImages.CiliumAgent, 2)),
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium-envoy":       jsonBytes(t, component("DaemonSet", "cilium-envoy", "component-uid-2", "cilium-envoy", profile.ExpectedImages.CiliumEnvoy, 2)),
		"/apis/apps/v1/namespaces/kube-system/deployments/cilium-operator":   jsonBytes(t, component("Deployment", "cilium-operator", "component-uid-3", "cilium-operator", profile.ExpectedImages.CiliumOperator, 1)),
		"/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium": jsonBytes(t, map[string]any{"apiVersion": "v1", "kind": "PodList", "items": []any{pod("cilium-b", "pod-uid-2", "node-b"), pod("cilium-a", "pod-uid-1", "node-a")}}),
	}}
	path := func() map[string]any { return map[string]any{"lastProbed": "2026-08-16T09:58:00Z"} }
	probeNode := func(name string) map[string]any {
		return map[string]any{"name": name,
			"host":            map[string]any{"primary-address": map[string]any{"http": path(), "icmp": path()}},
			"health-endpoint": map[string]any{"primary-address": map[string]any{"http": path(), "icmp": path()}},
		}
	}
	probe := &fakeFixedProbe{response: jsonBytes(t, map[string]any{"timestamp": "2026-08-16T09:59:00Z", "probeInterval": "1m36.566s", "nodes": []any{probeNode("node-b"), probeNode("node-a")}})}
	return policy, profile, management, workload, probe
}

func mustNetworkCollector(t *testing.T, policy Policy, management, workload NetworkRawGetter, probe FixedCiliumProbe) *NetworkSourceCollector {
	t.Helper()
	collector, err := NewNetworkSourceCollector(management, workload, probe, NetworkCollectorConfig{
		Namespace: "disposable-ok141", Name: "disposable-ok141", HCPName: "disposable-ok141-cilium", TargetClusterUID: policy.TargetClusterUID,
		Clock: func() time.Time { return time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector
}

func jsonBytes(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	return jsonBytes(t, value)
}

func reverseList(t *testing.T, raw []byte) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	items := value["items"]
	key := "items"
	if items == nil {
		items, key = value["nodes"], "nodes"
	}
	list := items.([]any)
	for left, right := 0, len(list)-1; left < right; left, right = left+1, right-1 {
		list[left], list[right] = list[right], list[left]
	}
	value[key] = list
	updated := jsonBytes(t, value)
	copy(raw, updated)
	if len(updated) != len(raw) {
		t.Fatalf("reordered fixture changed length: %d != %d", len(updated), len(raw))
	}
}
