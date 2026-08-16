package runner

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openkubes/ok-cluster/internal/observation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func TestKubernetesCiliumWebSocketExecutorUsesRemoteCommandV5(t *testing.T) {
	if os.Getenv("OK147_WEBSOCKET_INTEGRATION") != "yes" {
		t.Skip("set OK147_WEBSOCKET_INTEGRATION=yes to bind a local TLS listener")
	}
	identityCalls, execCalls := 0, 0
	upgrader := websocket.Upgrader{
		Subprotocols: []string{"v5.channel.k8s.io"},
		CheckOrigin:  func(*http.Request) bool { return true },
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer workload-token" {
			t.Error("WebSocket or identity request lacks the workload credential")
		}
		switch request.URL.Path {
		case "/api/v1/namespaces/kube-system/pods/cilium-abc12":
			identityCalls++
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"kube-system","name":"cilium-abc12","uid":"pod-uid-1","resourceVersion":"41"}}`)
		case "/api/v1/namespaces/kube-system/pods/cilium-abc12/exec":
			execCalls++
			if request.Method != http.MethodGet || request.Header.Get("Sec-Websocket-Protocol") != "v5.channel.k8s.io" {
				t.Errorf("unexpected RemoteCommand handshake: %s %#v", request.Method, request.Header)
			}
			connection, err := upgrader.Upgrade(response, request, nil)
			if err != nil {
				t.Errorf("upgrade test WebSocket: %v", err)
				return
			}
			defer connection.Close()
			payload := append([]byte{1}, []byte(`{"timestamp":"2026-08-16T12:00:00Z","nodes":[]}`)...)
			if err := connection.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				t.Errorf("write test stdout: %v", err)
				return
			}
			_ = connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	executor, err := newKubernetesCiliumWebSocketExecutor(server.URL, "workload-token", certificate, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := executor.Exec(context.Background(), validCiliumExecRequest())
	if err != nil {
		t.Fatal(err)
	}
	if identityCalls != 2 || execCalls != 1 || string(raw) != `{"timestamp":"2026-08-16T12:00:00Z","nodes":[]}` {
		t.Fatalf("unexpected real WebSocket boundary: identity=%d exec=%d raw=%q", identityCalls, execCalls, raw)
	}
}

func TestKubernetesCiliumWebSocketExecutorBindsUIDAndExactCommand(t *testing.T) {
	identityCalls := 0
	client := &http.Client{Transport: ciliumRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		identityCalls++
		if request.Method != http.MethodGet || request.URL.RequestURI() != "/api/v1/namespaces/kube-system/pods/cilium-abc12" || request.Header.Get("Authorization") != "Bearer workload-token" {
			t.Fatalf("unbounded Pod identity request: %s %s", request.Method, request.URL.RequestURI())
		}
		return ciliumPodResponse("cilium-abc12", "pod-uid-1", "41"), nil
	})}
	executor := newTestCiliumWebSocketExecutor(t, client)
	stream := &fakeRemoteCommandExecutor{stdout: []byte(`{"nodes":[]}`)}
	var observedConfig *rest.Config
	var observedMethod, observedURL string
	executor.factory = func(config *rest.Config, method, rawURL string) (remotecommand.Executor, error) {
		copy := *config
		copy.TLSClientConfig.CAData = append([]byte(nil), config.TLSClientConfig.CAData...)
		observedConfig, observedMethod, observedURL = &copy, method, rawURL
		return stream, nil
	}
	request := validCiliumExecRequest()
	raw, err := executor.Exec(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if identityCalls != 2 || stream.calls != 1 || string(raw) != `{"nodes":[]}` {
		t.Fatalf("unexpected exec outcome: identity=%d stream=%d raw=%q", identityCalls, stream.calls, raw)
	}
	if observedMethod != http.MethodGet || observedConfig.Host != "https://192.0.2.10:6443" || observedConfig.BearerToken != "workload-token" || string(observedConfig.CAData) != "test-ca" || !reflect.DeepEqual(observedConfig.NextProtos, []string{"http/1.1"}) || observedConfig.Proxy == nil {
		t.Fatalf("unsafe WebSocket config: %#v method=%s", observedConfig, observedMethod)
	}
	parsed, err := url.Parse(observedURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Path != "/api/v1/namespaces/kube-system/pods/cilium-abc12/exec" || !reflect.DeepEqual(query["command"], request.Command[:]) || query.Get("container") != "cilium-agent" || query.Get("stdin") != "false" || query.Get("stdout") != "true" || query.Get("stderr") != "true" || query.Get("tty") != "false" {
		t.Fatalf("WebSocket exec URL differs from fixed command: %s", observedURL)
	}
	if stream.options.Stdin != nil || stream.options.Stdout == nil || stream.options.Stderr == nil || stream.options.Tty {
		t.Fatalf("unsafe remote stream options: %#v", stream.options)
	}
}

func TestKubernetesCiliumWebSocketExecutorRejectsUIDRace(t *testing.T) {
	identityCalls := 0
	client := &http.Client{Transport: ciliumRoundTripFunc(func(*http.Request) (*http.Response, error) {
		identityCalls++
		uid := "pod-uid-1"
		if identityCalls == 2 {
			uid = "replacement-pod-uid"
		}
		return ciliumPodResponse("cilium-abc12", uid, "41"), nil
	})}
	executor := newTestCiliumWebSocketExecutor(t, client)
	stream := &fakeRemoteCommandExecutor{stdout: []byte(`{"nodes":[]}`)}
	executor.factory = func(*rest.Config, string, string) (remotecommand.Executor, error) { return stream, nil }
	if _, err := executor.Exec(context.Background(), validCiliumExecRequest()); err == nil || !strings.Contains(err.Error(), "runtime identity") {
		t.Fatalf("Pod UID replacement race was accepted: %v", err)
	}
	if identityCalls != 2 || stream.calls != 1 {
		t.Fatalf("unexpected UID-race boundary: identity=%d stream=%d", identityCalls, stream.calls)
	}
}

func TestKubernetesCiliumWebSocketExecutorFailsClosed(t *testing.T) {
	tests := map[string]struct {
		configure func(*KubernetesCiliumWebSocketExecutor, *fakeRemoteCommandExecutor)
		mutate    func(*observation.CiliumProbeExecRequest)
	}{
		"wrong command": {
			mutate: func(request *observation.CiliumProbeExecRequest) { request.Command[0] = "sh" },
		},
		"factory failure": {
			configure: func(executor *KubernetesCiliumWebSocketExecutor, _ *fakeRemoteCommandExecutor) {
				executor.factory = func(*rest.Config, string, string) (remotecommand.Executor, error) {
					return nil, errors.New("sensitive endpoint token")
				}
			},
		},
		"stream failure": {
			configure: func(_ *KubernetesCiliumWebSocketExecutor, stream *fakeRemoteCommandExecutor) {
				stream.err = errors.New("sensitive remote status")
			},
		},
		"stderr": {
			configure: func(_ *KubernetesCiliumWebSocketExecutor, stream *fakeRemoteCommandExecutor) {
				stream.stderr = []byte("sensitive diagnostic")
			},
		},
		"oversized stdout": {
			configure: func(_ *KubernetesCiliumWebSocketExecutor, stream *fakeRemoteCommandExecutor) {
				stream.stdout = bytes.Repeat([]byte("x"), maximumCiliumExecOutputBytes+1)
			},
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			identityCalls := 0
			client := &http.Client{Transport: ciliumRoundTripFunc(func(*http.Request) (*http.Response, error) {
				identityCalls++
				return ciliumPodResponse("cilium-abc12", "pod-uid-1", "41"), nil
			})}
			executor := newTestCiliumWebSocketExecutor(t, client)
			stream := &fakeRemoteCommandExecutor{stdout: []byte(`{"nodes":[]}`)}
			executor.factory = func(*rest.Config, string, string) (remotecommand.Executor, error) { return stream, nil }
			if testCase.configure != nil {
				testCase.configure(executor, stream)
			}
			request := validCiliumExecRequest()
			if testCase.mutate != nil {
				testCase.mutate(&request)
			}
			if _, err := executor.Exec(context.Background(), request); err == nil {
				t.Fatal("unsafe WebSocket exec outcome accepted")
			} else if strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("raw WebSocket detail leaked: %v", err)
			}
			if name == "wrong command" && (identityCalls != 0 || stream.calls != 0) {
				t.Fatal("invalid command crossed the API boundary")
			}
		})
	}
}

func TestKubernetesCiliumWebSocketExecutorRejectsForeignInitialPod(t *testing.T) {
	client := &http.Client{Transport: ciliumRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return ciliumPodResponse("cilium-abc12", "foreign-uid", "41"), nil
	})}
	executor := newTestCiliumWebSocketExecutor(t, client)
	factoryCalls := 0
	executor.factory = func(*rest.Config, string, string) (remotecommand.Executor, error) {
		factoryCalls++
		return &fakeRemoteCommandExecutor{}, nil
	}
	if _, err := executor.Exec(context.Background(), validCiliumExecRequest()); err == nil || factoryCalls != 0 {
		t.Fatalf("foreign initial Pod reached WebSocket exec: factory=%d err=%v", factoryCalls, err)
	}
}

func newTestCiliumWebSocketExecutor(t *testing.T, client *http.Client) *KubernetesCiliumWebSocketExecutor {
	t.Helper()
	executor, err := newKubernetesCiliumWebSocketExecutor("https://192.0.2.10:6443", "workload-token", []byte("test-ca"), client)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func validCiliumExecRequest() observation.CiliumProbeExecRequest {
	request, err := observation.NewFixedCiliumProbeExecRequest("cilium-abc12", "pod-uid-1")
	if err != nil {
		panic(err)
	}
	return request
}

type fakeRemoteCommandExecutor struct {
	stdout  []byte
	stderr  []byte
	err     error
	options remotecommand.StreamOptions
	calls   int
}

func (executor *fakeRemoteCommandExecutor) Stream(options remotecommand.StreamOptions) error {
	return executor.StreamWithContext(context.Background(), options)
}

func (executor *fakeRemoteCommandExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	executor.calls++
	executor.options = options
	if executor.err != nil {
		return executor.err
	}
	if len(executor.stdout) != 0 {
		if _, err := options.Stdout.Write(executor.stdout); err != nil {
			return err
		}
	}
	if len(executor.stderr) != 0 {
		if _, err := options.Stderr.Write(executor.stderr); err != nil {
			return err
		}
	}
	return nil
}

type ciliumRoundTripFunc func(*http.Request) (*http.Response, error)

func (function ciliumRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func ciliumPodResponse(name, uid, resourceVersion string) *http.Response {
	body := `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"kube-system","name":"` + name + `","uid":"` + uid + `","resourceVersion":"` + resourceVersion + `"}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
