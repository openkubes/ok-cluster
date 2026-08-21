package observation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KubernetesNetworkReaderConfig binds one bearer credential and one explicitly
// configured TLS client to one Kubernetes API endpoint. The plane-specific
// constructors derive their request allowlists internally.
type KubernetesNetworkReaderConfig struct {
	Endpoint          string
	BearerToken       string
	ClientCertificate bool
	Client            *http.Client
}

// KubernetesNetworkReader implements NetworkRawGetter without exposing
// discovery, arbitrary list paths, watch, mutation, retry, or redirects.
type KubernetesNetworkReader struct {
	endpoint          *url.URL
	token             string
	clientCertificate bool
	client            *http.Client
	allowed           map[string]struct{}
}

func NewKubernetesManagementNetworkReader(config KubernetesNetworkReaderConfig, namespace, name, hcpName string) (*KubernetesNetworkReader, error) {
	if !validDNSLabel(namespace) || !validDNSLabel(name) || !validDNSLabel(hcpName) {
		return nil, errors.New("management network reader object identity is invalid")
	}
	hcpPath, hrpPath := managementNetworkPaths(namespace, name, hcpName)
	return newKubernetesNetworkReader(config, []string{hcpPath, hrpPath})
}

func NewKubernetesWorkloadNetworkReader(config KubernetesNetworkReaderConfig) (*KubernetesNetworkReader, error) {
	return newKubernetesNetworkReader(config, workloadNetworkPaths())
}

func newKubernetesNetworkReader(config KubernetesNetworkReaderConfig, allowed []string) (*KubernetesNetworkReader, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("network reader Kubernetes endpoint is invalid")
	}
	if endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errors.New("network reader Kubernetes endpoint must not contain a path")
	}
	host := endpoint.Hostname()
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (host == "127.0.0.1" || host == "::1" || host == "localhost")) {
		return nil, errors.New("network reader Kubernetes endpoint must use HTTPS")
	}
	tokenMode := config.BearerToken != ""
	if tokenMode == config.ClientCertificate || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") {
		return nil, errors.New("network reader Kubernetes transport credential is invalid")
	}
	if config.Client == nil {
		return nil, errors.New("network reader requires an explicitly configured HTTP client")
	}
	paths := make(map[string]struct{}, len(allowed))
	for _, path := range allowed {
		if _, duplicate := paths[path]; duplicate {
			return nil, errors.New("network reader allowlist contains a duplicate path")
		}
		paths[path] = struct{}{}
	}
	client := *config.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesNetworkReader{
		endpoint: endpoint, token: config.BearerToken, clientCertificate: config.ClientCertificate,
		client: &client, allowed: paths,
	}, nil
}

func (reader *KubernetesNetworkReader) Get(ctx context.Context, path string) ([]byte, error) {
	if _, allowed := reader.allowed[path]; !allowed {
		return nil, errors.New("network reader path is outside the fixed allowlist")
	}
	reference, err := url.ParseRequestURI(path)
	if err != nil || reference.IsAbs() || reference.Host != "" || !strings.HasPrefix(reference.Path, "/") {
		return nil, errors.New("network reader allowlisted path is invalid")
	}
	endpoint := *reader.endpoint
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery = reference.Path, reference.RawPath, reference.RawQuery
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errors.New("construct bounded network source request")
	}
	request.Header.Set("Accept", "application/json")
	if !reader.clientCertificate {
		request.Header.Set("Authorization", "Bearer "+reader.token)
	}
	response, err := reader.client.Do(request)
	if err != nil {
		return nil, errors.New("bounded network source request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumNetworkSourceBytes+1))
	if readErr != nil || len(raw) > maximumNetworkSourceBytes {
		return nil, errors.New("bounded network source response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bounded network source request returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("bounded network source response is not JSON")
	}
	return raw, nil
}

// CiliumProbeExecRequest is the complete immutable request accepted by the
// low-level Kubernetes Pod-exec transport. The high-level probe constructs it;
// callers cannot supply a command through FixedCiliumProbe.
type CiliumProbeExecRequest struct {
	Namespace string
	PodName   string
	PodUID    string
	Container string
	Command   [5]string
}

var fixedCiliumProbeCommand = [5]string{"cilium-health", "status", "--probe", "--output", "json"}

// NewFixedCiliumProbeExecRequest is the single authoritative constructor for
// the command transported by the runner. It never accepts command arguments.
func NewFixedCiliumProbeExecRequest(podName, podUID string) (CiliumProbeExecRequest, error) {
	request := CiliumProbeExecRequest{
		Namespace: "kube-system", PodName: podName, PodUID: podUID, Container: "cilium-agent",
		Command: fixedCiliumProbeCommand,
	}
	if err := ValidateFixedCiliumProbeExecRequest(request); err != nil {
		return CiliumProbeExecRequest{}, err
	}
	return request, nil
}

// ValidateFixedCiliumProbeExecRequest prevents a low-level transport from
// being reused as an arbitrary Pod command surface.
func ValidateFixedCiliumProbeExecRequest(request CiliumProbeExecRequest) error {
	if request.Namespace != "kube-system" || request.Container != "cilium-agent" || request.Command != fixedCiliumProbeCommand || !validDNSLabel(request.PodName) || !validUID(request.PodUID) {
		return errors.New("Cilium probe exec request differs from the fixed boundary")
	}
	return nil
}

type CiliumProbePodExecutor interface {
	Exec(context.Context, CiliumProbeExecRequest) ([]byte, error)
}

// KubernetesFixedCiliumProbe binds the only permitted command. The low-level
// transport must verify the Pod UID immediately before opening its exec stream.
type KubernetesFixedCiliumProbe struct {
	executor CiliumProbePodExecutor
}

func NewKubernetesFixedCiliumProbe(executor CiliumProbePodExecutor) (*KubernetesFixedCiliumProbe, error) {
	if executor == nil {
		return nil, errors.New("fixed Cilium probe requires a Pod executor")
	}
	return &KubernetesFixedCiliumProbe{executor: executor}, nil
}

func (probe *KubernetesFixedCiliumProbe) Probe(ctx context.Context, podName, podUID string) ([]byte, error) {
	request, err := NewFixedCiliumProbeExecRequest(podName, podUID)
	if err != nil {
		return nil, err
	}
	raw, err := probe.executor.Exec(ctx, request)
	if err != nil {
		return nil, errors.New("fixed Cilium Pod exec failed")
	}
	if len(raw) == 0 || len(raw) > maximumNetworkSourceBytes {
		return nil, errors.New("fixed Cilium Pod exec response size is invalid")
	}
	return append([]byte(nil), raw...), nil
}

func managementNetworkPaths(namespace, name, hcpName string) (string, string) {
	hcpPath := "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/" + namespace + "/helmchartproxies/" + hcpName
	selector := "cluster.x-k8s.io/cluster-name=" + name + ",helmreleaseproxy.addons.cluster.x-k8s.io/helmchartproxy-name=" + hcpName
	hrpPath := "/apis/addons.cluster.x-k8s.io/v1alpha1/namespaces/" + namespace + "/helmreleaseproxies?labelSelector=" + url.QueryEscape(selector)
	return hcpPath, hrpPath
}

func workloadNetworkPaths() []string {
	return []string{
		"/api/v1/nodes",
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium",
		"/apis/apps/v1/namespaces/kube-system/daemonsets/cilium-envoy",
		"/apis/apps/v1/namespaces/kube-system/deployments/cilium-operator",
		"/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app%3Dcilium",
	}
}
