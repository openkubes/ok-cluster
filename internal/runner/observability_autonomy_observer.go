package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	ObservabilityAutonomyProfileFormat = "ok147-observability-autonomy-profile/v1"
	maximumAutonomyResponseBytes       = 2 * 1024 * 1024
)

type KubernetesObservabilityAutonomyObserverConfig struct {
	Endpoint         string
	TokenFile        string
	CAFile           string
	CABundleDigest   string
	TargetClusterUID string
	Profile          ObservabilityCapabilityCheckProfile
}

// KubernetesObservabilityAutonomyObserver reads only the standard profile's
// four Services and their four service-name-scoped EndpointSlice collections.
// It has no discovery, arbitrary list, mutation, repair or retry surface.
type KubernetesObservabilityAutonomyObserver struct {
	endpoint         *url.URL
	token            string
	targetClusterUID string
	profile          ObservabilityCapabilityCheckProfile
	profileDigest    string
	client           *http.Client
}

type observabilityAutonomyProfileDocument struct {
	Format             string                        `json:"format"`
	CapabilityProfile  string                        `json:"capabilityProfile"`
	Namespace          string                        `json:"namespace"`
	Services           []observabilityServiceBinding `json:"services"`
	ServiceType        string                        `json:"serviceType"`
	EndpointTargetKind string                        `json:"endpointTargetKind"`
	EndpointNamespace  string                        `json:"endpointNamespace"`
	ExternalFields     []string                      `json:"externalFields"`
}

type autonomyService struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Type         string   `json:"type"`
		ClusterIP    string   `json:"clusterIP"`
		ExternalName string   `json:"externalName"`
		ExternalIPs  []string `json:"externalIPs"`
		Ports        []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []json.RawMessage `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type autonomyEndpointSliceList struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Items      []autonomyEndpointSlice `json:"items"`
}

type autonomyEndpointSlice struct {
	AddressType string `json:"addressType"`
	Metadata    struct {
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Ports []struct {
		Port     *int   `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
	Endpoints []struct {
		Addresses  []string `json:"addresses"`
		Conditions struct {
			Ready       *bool `json:"ready"`
			Terminating *bool `json:"terminating"`
		} `json:"conditions"`
		TargetRef *struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"targetRef"`
	} `json:"endpoints"`
}

func OpenKubernetesObservabilityAutonomyObserver(config KubernetesObservabilityAutonomyObserverConfig) (*KubernetesObservabilityAutonomyObserver, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	endpoint, parseErr := url.Parse(config.Endpoint)
	if err != nil || parseErr != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Path != "" && endpoint.Path != "/" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		!runtimeInputUIDPattern.MatchString(config.TargetClusterUID) || config.Profile.Digest() == "" || config.Profile.Digest() != standard.Digest() ||
		config.TokenFile == "" || config.CAFile == "" || !platformInputDigestPattern.MatchString(config.CABundleDigest) {
		return nil, errors.New("observability autonomy observer binding is invalid")
	}
	token, ca, boundedClient, err := openBoundedKubernetesMaterial(config.TokenFile, config.CAFile)
	if err != nil || digest.SHA256(ca) != config.CABundleDigest {
		return nil, errors.New("open observability autonomy Kubernetes authority")
	}
	client := boundedClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	profileDigest, err := observabilityAutonomyProfileDigest(config.Profile)
	if err != nil {
		return nil, errors.New("derive observability autonomy profile")
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesObservabilityAutonomyObserver{
		endpoint: endpoint, token: token, targetClusterUID: config.TargetClusterUID,
		profile: config.Profile, profileDigest: profileDigest, client: client,
	}, nil
}

func (observer *KubernetesObservabilityAutonomyObserver) Observe(ctx context.Context, request ObservabilityIndependentEvidenceCollectionRequest) (ObservabilityCollectorAutonomyObservation, error) {
	if observer == nil || observer.endpoint == nil || observer.client == nil || observer.token == "" ||
		request.TargetClusterUID != observer.targetClusterUID || request.ProfileDigest != observer.profile.Digest() || request.AlertName != observer.profile.alertName {
		return ObservabilityCollectorAutonomyObservation{}, errors.New("observability autonomy observation identity is invalid")
	}
	if _, _, err := canonicalObservabilityIndependentEvidenceCollectionRequest(request); err != nil {
		return ObservabilityCollectorAutonomyObservation{}, errors.New("observability autonomy collection request is invalid")
	}
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return ObservabilityCollectorAutonomyObservation{}, errors.New("observability autonomy observation requires a live deadline")
	}
	bindings := []observabilityServiceBinding{observer.profile.prometheus, observer.profile.grafana, observer.profile.opensearch, observer.profile.alertmanager}
	ready, externalDependencies := true, 0
	for _, binding := range bindings {
		serviceRaw, err := observer.get(ctx, "/api/v1/namespaces/"+observer.profile.namespace+"/services/"+binding.Name, "")
		if err != nil {
			return ObservabilityCollectorAutonomyObservation{}, errors.New("read exact observability Service")
		}
		serviceReady, serviceExternal, err := evaluateAutonomyService(serviceRaw, observer.profile.namespace, binding)
		if err != nil {
			return ObservabilityCollectorAutonomyObservation{}, err
		}
		slicesPath := "/apis/discovery.k8s.io/v1/namespaces/" + observer.profile.namespace + "/endpointslices"
		slicesQuery := "labelSelector=" + url.QueryEscape("kubernetes.io/service-name="+binding.Name)
		slicesRaw, err := observer.get(ctx, slicesPath, slicesQuery)
		if err != nil {
			return ObservabilityCollectorAutonomyObservation{}, errors.New("read bounded observability EndpointSlices")
		}
		endpointsReady, endpointExternal, err := evaluateAutonomyEndpointSlices(slicesRaw, observer.profile.namespace, binding.Name)
		if err != nil {
			return ObservabilityCollectorAutonomyObservation{}, err
		}
		ready = ready && serviceReady && endpointsReady
		externalDependencies += serviceExternal + endpointExternal
	}
	return ObservabilityCollectorAutonomyObservation{
		ClusterLocalServicesReady:   ready && externalDependencies == 0,
		ExternalClusterDependencies: externalDependencies, AutonomyProfileDigest: observer.profileDigest,
	}, nil
}

func (observer *KubernetesObservabilityAutonomyObserver) get(ctx context.Context, path, rawQuery string) ([]byte, error) {
	endpoint := *observer.endpoint
	endpoint.Path = path
	endpoint.RawQuery = rawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("construct observability autonomy request")
	}
	request.Header.Set("Authorization", "Bearer "+observer.token)
	request.Header.Set("Accept", "application/json")
	response, err := observer.client.Do(request)
	if err != nil {
		return nil, errors.New("request observability autonomy source")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || mediaType != "application/json" {
		return nil, errors.New("observability autonomy source response is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumAutonomyResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumAutonomyResponseBytes {
		return nil, errors.New("observability autonomy source response exceeds accepted size")
	}
	return raw, nil
}

func evaluateAutonomyService(raw []byte, namespace string, binding observabilityServiceBinding) (bool, int, error) {
	var service autonomyService
	if err := json.Unmarshal(raw, &service); err != nil || service.APIVersion != "v1" || service.Kind != "Service" ||
		service.Metadata.Name != binding.Name || service.Metadata.Namespace != namespace {
		return false, 0, errors.New("observability Service identity is invalid")
	}
	external := 0
	if service.Spec.Type != "ClusterIP" || service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" || service.Spec.ExternalName != "" {
		external++
	}
	external += len(service.Spec.ExternalIPs) + len(service.Status.LoadBalancer.Ingress)
	portReady := false
	for _, port := range service.Spec.Ports {
		if port.Port == binding.Port && (port.Protocol == "" || port.Protocol == "TCP") {
			portReady = true
		}
	}
	return portReady && external == 0, external, nil
}

func evaluateAutonomyEndpointSlices(raw []byte, namespace, serviceName string) (bool, int, error) {
	var list autonomyEndpointSliceList
	if err := json.Unmarshal(raw, &list); err != nil || list.APIVersion != "discovery.k8s.io/v1" || list.Kind != "EndpointSliceList" {
		return false, 0, errors.New("observability EndpointSlice collection is invalid")
	}
	readyEndpoints, external := 0, 0
	for _, slice := range list.Items {
		if slice.Metadata.Namespace != namespace || slice.Metadata.Labels["kubernetes.io/service-name"] != serviceName ||
			slice.AddressType != "IPv4" && slice.AddressType != "IPv6" {
			return false, 0, errors.New("observability EndpointSlice identity is invalid")
		}
		portReady := false
		for _, port := range slice.Ports {
			if port.Port != nil && *port.Port > 0 && (port.Protocol == "" || port.Protocol == "TCP") {
				portReady = true
			}
		}
		if !portReady {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			terminating := endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating
			isReady := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != namespace || endpoint.TargetRef.Name == "" {
				external++
				continue
			}
			if isReady && !terminating && len(endpoint.Addresses) > 0 {
				readyEndpoints++
			}
		}
	}
	return readyEndpoints > 0 && external == 0, external, nil
}

func observabilityAutonomyProfileDigest(profile ObservabilityCapabilityCheckProfile) (string, error) {
	services := []observabilityServiceBinding{profile.prometheus, profile.grafana, profile.opensearch, profile.alertmanager}
	sort.Slice(services, func(left, right int) bool { return services[left].Name < services[right].Name })
	document := observabilityAutonomyProfileDocument{
		Format: ObservabilityAutonomyProfileFormat, CapabilityProfile: profile.Digest(), Namespace: profile.namespace,
		Services: services, ServiceType: "ClusterIP", EndpointTargetKind: "Pod", EndpointNamespace: profile.namespace,
		ExternalFields: []string{"spec.externalIPs", "spec.externalName", "status.loadBalancer.ingress", "endpoint.targetRef.namespace"},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encode autonomy profile: %w", err)
	}
	return digest.SHA256(raw), nil
}

var _ ObservabilityCollectorAutonomyObserver = (*KubernetesObservabilityAutonomyObserver)(nil)
