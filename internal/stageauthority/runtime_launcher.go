package stageauthority

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	RuntimeLaunchReceiptFormat       = "ok147-bounded-stage-authority-runtime-launch-receipt/v1"
	maximumRuntimeResponseBytes      = 4 * 1024 * 1024
	maximumRuntimeInstallerCABytes   = 1024 * 1024
	maximumRuntimeInstallerTokenSize = 64 * 1024
)

type RuntimeLauncherConfig struct {
	Endpoint              string
	Authority             string
	TokenFile             string
	CAFile                string
	CABundleDigest        string
	ExpectedPackageDigest string
}

type RuntimeInstalledObject struct {
	Order                 int    `json:"order"`
	APIVersion            string `json:"apiVersion"`
	Kind                  string `json:"kind"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	ObjectDigest          string `json:"objectDigest"`
	UIDDigest             string `json:"uidDigest"`
	ResourceVersionDigest string `json:"resourceVersionDigest"`
	State                 string `json:"state"`
}

type RuntimeLaunchReceipt struct {
	Format        string                   `json:"format"`
	Authority     string                   `json:"authority"`
	PackageDigest string                   `json:"packageDigest"`
	State         string                   `json:"state"`
	MutationState string                   `json:"mutationState"`
	Results       []RuntimeInstalledObject `json:"results"`
}

type runtimeInstallerClientConfig struct {
	Endpoint, BearerToken, Authority string
	Client                           *http.Client
}

// KubernetesRuntimeLauncher is single-use. It has no update, patch, delete,
// apply, list, watch, adoption, rollback or retry operation.
type KubernetesRuntimeLauncher struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	token    string
	client   *http.Client
	plan     RuntimeInstallationPlan
	objects  []runtimeInstallObject
}

func OpenKubernetesRuntimeLauncher(config RuntimeLauncherConfig, packaged VerifiedRuntimePackage) (*KubernetesRuntimeLauncher, error) {
	receipt, err := packaged.Receipt()
	if err != nil || receipt.PackageDigest != config.ExpectedPackageDigest || !digestPattern.MatchString(config.CABundleDigest) {
		return nil, errors.New("bounded stage authority launcher binding is invalid")
	}
	tokenRaw, err := readPrivateRegular(config.TokenFile, maximumRuntimeInstallerTokenSize, true)
	if err != nil {
		return nil, errors.New("read bounded stage authority installer token")
	}
	token := string(tokenRaw)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("bounded stage authority installer token is invalid")
	}
	ca, err := readPrivateRegular(config.CAFile, maximumRuntimeInstallerCABytes, false)
	if err != nil || digest.SHA256(ca) != config.CABundleDigest {
		return nil, errors.New("bounded stage authority installer CA differs")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("bounded stage authority installer CA contains no certificate")
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
	}}
	return newKubernetesRuntimeLauncher(runtimeInstallerClientConfig{
		Endpoint: config.Endpoint, BearerToken: token, Authority: config.Authority, Client: client,
	}, packaged)
}

func newKubernetesRuntimeLauncher(config runtimeInstallerClientConfig, packaged VerifiedRuntimePackage) (*KubernetesRuntimeLauncher, error) {
	plan, objects, err := prepareRuntimeInstallation(packaged, config.Authority)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("bounded stage authority installer endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("bounded stage authority installer endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("bounded stage authority installer credential is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesRuntimeLauncher{endpoint: endpoint, token: config.BearerToken, client: &client, plan: plan, objects: objects}, nil
}

// Launch first proves all six exact names absent, then POSTs the immutable
// package in fixed order. Any attempted write consumes this launcher forever.
func (launcher *KubernetesRuntimeLauncher) Launch(ctx context.Context) (RuntimeLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil {
		return receipt, errors.New("bounded stage authority launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopRuntimeLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("bounded stage authority launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil {
			return stopRuntimeLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		if status == http.StatusOK {
			return stopRuntimeLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("bounded stage authority runtime object already exists"))
		}
		if status != http.StatusNotFound {
			return stopRuntimeLaunch(receipt, "STOPPED_ZERO_WRITE", fmt.Errorf("bounded stage authority GET returned HTTP %d", status))
		}
	}

	receipt.State = "CREATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil {
			return stopRuntimeLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stopRuntimeLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", fmt.Errorf("bounded stage authority POST returned HTTP %d", status))
		}
		uid, resourceVersion, err := verifyRuntimeCreatedObject(raw, object.raw)
		if err != nil {
			return stopRuntimeLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, RuntimeInstalledObject{
			Order: object.plan.Order, APIVersion: object.plan.APIVersion, Kind: object.plan.Kind,
			Namespace: object.plan.Namespace, Name: object.plan.Name, ObjectDigest: object.plan.ObjectDigest,
			UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (launcher *KubernetesRuntimeLauncher) newReceipt() RuntimeLaunchReceipt {
	receipt := RuntimeLaunchReceipt{Format: RuntimeLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []RuntimeInstalledObject{}}
	if launcher != nil {
		receipt.Authority, receipt.PackageDigest = launcher.plan.Authority, launcher.plan.PackageDigest
	}
	return receipt
}

func stopRuntimeLaunch(receipt RuntimeLaunchReceipt, state string, err error) (RuntimeLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (launcher *KubernetesRuntimeLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded stage authority installer request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded stage authority %s request failed", method)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumRuntimeResponseBytes+1))
	if err != nil || len(raw) > maximumRuntimeResponseBytes {
		return nil, 0, errors.New("bounded stage authority response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded stage authority response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func verifyRuntimeCreatedObject(raw, desiredRaw []byte) (string, string, error) {
	var observed, desired map[string]any
	if json.Unmarshal(raw, &observed) != nil || json.Unmarshal(desiredRaw, &desired) != nil ||
		!normalizeRuntimeAPIResponse(desired, observed) || !runtimeSubset(desired, observed) {
		return "", "", errors.New("created bounded stage authority object differs from verified package")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if uid == "" || resourceVersion == "" || strings.ContainsAny(uid+resourceVersion, "\r\n") {
		return "", "", errors.New("created bounded stage authority object lacks runtime identity")
	}
	return uid, resourceVersion, nil
}

// Kubernetes omits an explicitly empty NetworkPolicy egress list when it
// serializes the stored object. With policyTypes containing Egress, omitted and
// empty both mean deny all egress. Keep this equivalence deliberately scoped to
// that one API field; every other desired field remains an exact subset check.
func normalizeRuntimeAPIResponse(desired, observed map[string]any) bool {
	if desired["apiVersion"] != "networking.k8s.io/v1" || desired["kind"] != "NetworkPolicy" {
		return true
	}
	desiredSpec, desiredOK := desired["spec"].(map[string]any)
	observedSpec, observedOK := observed["spec"].(map[string]any)
	if !desiredOK || !observedOK {
		return false
	}
	desiredEgress, bound := desiredSpec["egress"].([]any)
	if !bound || len(desiredEgress) != 0 {
		return true
	}
	if _, present := observedSpec["egress"]; !present {
		observedSpec["egress"] = []any{}
	}
	return true
}

func runtimeSubset(expected, observed any) bool {
	switch wanted := expected.(type) {
	case map[string]any:
		got, ok := observed.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range wanted {
			if !runtimeSubset(value, got[key]) {
				return false
			}
		}
		return true
	case []any:
		got, ok := observed.([]any)
		if !ok || len(got) != len(wanted) {
			return false
		}
		for index := range wanted {
			if !runtimeSubset(wanted[index], got[index]) {
				return false
			}
		}
		return true
	default:
		return expected == observed
	}
}
