package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/observation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	maximumCiliumExecOutputBytes = 4 * 1024 * 1024
	maximumCiliumExecErrorBytes  = 64 * 1024
	defaultCiliumExecTimeout     = 30 * time.Second
)

type websocketExecutorFactory func(*rest.Config, string, string) (remotecommand.Executor, error)

// KubernetesCiliumWebSocketExecutor executes only the fixed Cilium health
// command over Kubernetes RemoteCommand v5 WebSockets. It performs exact Pod
// UID checks immediately before and after exec to reject name-reuse races.
type KubernetesCiliumWebSocketExecutor struct {
	endpoint       *url.URL
	token          string
	caData         []byte
	identityClient *http.Client
	timeout        time.Duration
	factory        websocketExecutorFactory
}

func newKubernetesCiliumWebSocketExecutor(endpoint, token string, caData []byte, client *http.Client) (*KubernetesCiliumWebSocketExecutor, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Cilium WebSocket executor Kubernetes endpoint is invalid")
	}
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") || len(caData) == 0 || client == nil {
		return nil, errors.New("Cilium WebSocket executor credential material is invalid")
	}
	parsed.Path, parsed.RawPath = "", ""
	return &KubernetesCiliumWebSocketExecutor{
		endpoint: parsed, token: token, caData: append([]byte(nil), caData...), identityClient: client,
		timeout: defaultCiliumExecTimeout, factory: remotecommand.NewWebSocketExecutor,
	}, nil
}

func (executor *KubernetesCiliumWebSocketExecutor) Exec(ctx context.Context, request observation.CiliumProbeExecRequest) ([]byte, error) {
	if err := observation.ValidateFixedCiliumProbeExecRequest(request); err != nil {
		return nil, errors.New("Cilium WebSocket exec request differs from the fixed boundary")
	}
	bounded, cancel := context.WithTimeout(ctx, executor.timeout)
	defer cancel()
	if err := executor.verifyPodUID(bounded, request.PodName, request.PodUID); err != nil {
		return nil, err
	}

	execURL := *executor.endpoint
	execURL.Path = "/api/v1/namespaces/kube-system/pods/" + request.PodName + "/exec"
	query := url.Values{}
	for _, argument := range request.Command {
		query.Add("command", argument)
	}
	query.Set("container", request.Container)
	query.Set("stdin", "false")
	query.Set("stdout", "true")
	query.Set("stderr", "true")
	query.Set("tty", "false")
	execURL.RawQuery = query.Encode()
	restConfig := &rest.Config{
		Host: execURL.Scheme + "://" + execURL.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: append([]byte(nil), executor.caData...), NextProtos: []string{"http/1.1"},
		},
		BearerToken: executor.token, Timeout: executor.timeout, DisableCompression: true,
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
	stream, err := executor.factory(restConfig, http.MethodGet, execURL.String())
	if err != nil {
		return nil, errors.New("construct fixed Cilium WebSocket stream")
	}
	stdout := newBoundedExecBuffer(maximumCiliumExecOutputBytes)
	stderr := newBoundedExecBuffer(maximumCiliumExecErrorBytes)
	streamErr := stream.StreamWithContext(bounded, remotecommand.StreamOptions{Stdout: stdout, Stderr: stderr, Tty: false})
	postErr := executor.verifyPodUID(bounded, request.PodName, request.PodUID)
	if streamErr != nil {
		return nil, errors.New("fixed Cilium WebSocket stream failed")
	}
	if postErr != nil {
		return nil, postErr
	}
	if stderr.Len() != 0 || stderr.Exceeded() {
		return nil, errors.New("fixed Cilium WebSocket stream returned stderr")
	}
	if stdout.Len() == 0 || stdout.Exceeded() {
		return nil, errors.New("fixed Cilium WebSocket stdout size is invalid")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (executor *KubernetesCiliumWebSocketExecutor) verifyPodUID(ctx context.Context, podName, expectedUID string) error {
	endpoint := *executor.endpoint
	endpoint.Path = "/api/v1/namespaces/kube-system/pods/" + podName
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.New("construct exact Cilium Pod identity request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+executor.token)
	response, err := executor.identityClient.Do(request)
	if err != nil {
		return errors.New("exact Cilium Pod identity request failed")
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumNetworkSourceIdentityBytes+1))
	if readErr != nil || len(raw) > maximumNetworkSourceIdentityBytes {
		return errors.New("exact Cilium Pod identity response exceeds accepted size")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("exact Cilium Pod identity request returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("exact Cilium Pod identity response is not JSON")
	}
	var pod struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Namespace       string `json:"namespace"`
			Name            string `json:"name"`
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&pod); err != nil {
		return errors.New("exact Cilium Pod identity response is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("exact Cilium Pod identity response has trailing JSON")
	}
	if pod.APIVersion != "v1" || pod.Kind != "Pod" || pod.Metadata.Namespace != "kube-system" || pod.Metadata.Name != podName || pod.Metadata.UID != expectedUID || pod.Metadata.ResourceVersion == "" {
		return errors.New("exact Cilium Pod runtime identity differs from the selected Pod")
	}
	return nil
}

type boundedExecBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func newBoundedExecBuffer(maximum int) *boundedExecBuffer {
	return &boundedExecBuffer{maximum: maximum}
}

func (buffer *boundedExecBuffer) Write(raw []byte) (int, error) {
	if len(raw) > buffer.maximum-buffer.buffer.Len() {
		buffer.exceeded = true
		return 0, errors.New("bounded exec stream exceeded its limit")
	}
	return buffer.buffer.Write(raw)
}

func (buffer *boundedExecBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }
func (buffer *boundedExecBuffer) Len() int       { return buffer.buffer.Len() }
func (buffer *boundedExecBuffer) Exceeded() bool { return buffer.exceeded }

const maximumNetworkSourceIdentityBytes = 1024 * 1024
