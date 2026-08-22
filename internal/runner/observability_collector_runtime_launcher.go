package runner

import (
	"bytes"
	"context"
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
	ObservabilityCollectorRuntimeInstallationPlanFormat = "ok147-observability-collector-runtime-installation-plan/v1"
	ObservabilityCollectorRuntimeLaunchReceiptFormat    = "ok147-observability-collector-runtime-launch-receipt/v1"
)

type ObservabilityCollectorRuntimeInstallationPlan struct {
	Format               string                                   `json:"format"`
	State                string                                   `json:"state"`
	RunID                string                                   `json:"runId"`
	PackageDigest        string                                   `json:"packageDigest"`
	ManifestDigest       string                                   `json:"manifestDigest"`
	RuntimeBindingDigest string                                   `json:"runtimeBindingDigest"`
	TargetIdentityDigest string                                   `json:"targetIdentityDigest"`
	Authority            string                                   `json:"authority"`
	Prerequisites        []FullRunExecutionActivationPrerequisite `json:"prerequisites"`
	Creates              []SubmissionStageCreatePlan              `json:"creates"`
	MutationAllowed      bool                                     `json:"mutationAllowed"`
}

type ObservabilityCollectorRuntimeLauncherConfig struct {
	Authority             KubernetesAuthorityConfig
	ExpectedPackageDigest string
}

type ObservabilityCollectorRuntimeLaunchReceipt struct {
	Format               string                           `json:"format"`
	RunID                string                           `json:"runId"`
	PackageDigest        string                           `json:"packageDigest"`
	ManifestDigest       string                           `json:"manifestDigest"`
	RuntimeBindingDigest string                           `json:"runtimeBindingDigest"`
	TargetIdentityDigest string                           `json:"targetIdentityDigest"`
	Authority            string                           `json:"authority"`
	State                string                           `json:"state"`
	MutationState        string                           `json:"mutationState"`
	Results              []SubmissionStageInstalledObject `json:"results"`
}

// PlanObservabilityCollectorRuntimeInstallation derives the exact workload
// Secret -> Service -> NetworkPolicy -> Job sequence without opening a
// credential or contacting Kubernetes.
func PlanObservabilityCollectorRuntimeInstallation(packaged VerifiedObservabilityCollectorRuntimePackage) (ObservabilityCollectorRuntimeInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return ObservabilityCollectorRuntimeInstallationPlan{}, err
	}
	objects, err := decodeFullRunActivationObjects(packaged.raw, 4)
	if err != nil {
		return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("decode observability collector runtime package")
	}
	activationObject, err := json.Marshal(objects[0])
	if err != nil {
		return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("encode observability collector activation object")
	}
	activation, err := observabilityCollectorActivationFromSecret(activationObject)
	if err != nil || activation.ManifestDigest != receipt.ManifestDigest || activation.RuntimeBindingDigest != receipt.RuntimeBindingDigest {
		return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector activation binding differs")
	}
	targetIdentity := digest.SHA256([]byte(activation.TargetClusterUID))
	if !stageReceiptPrefixDigestPattern.MatchString(targetIdentity) {
		return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector target identity is invalid")
	}

	creates := make([]SubmissionStageCreatePlan, 0, 4)
	runID := ""
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != receipt.ObjectKinds[index] {
			return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector create order differs")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector object identity is invalid")
		}
		collection, objectPath, err := observabilityCollectorCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return ObservabilityCollectorRuntimeInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("encode observability collector object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: http.MethodGet, ObjectPath: objectPath, CreateMethod: http.MethodPost,
			CollectionPath: collection, ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "Secret":
			annotations, _ := metadata["annotations"].(map[string]any)
			labels, _ := metadata["labels"].(map[string]any)
			data, _ := object["data"].(map[string]any)
			if name != receipt.ActivationSecret || object["immutable"] != true || object["type"] != "Opaque" ||
				labels["openkubes.io/stage-id"] != "independent-evidence" || annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest ||
				annotations["openkubes.io/activation-digest"] != receipt.ActivationDigest || len(data) != 7 {
				return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector Secret semantics differ")
			}
		case "Service":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["selector"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if spec["type"] != "LoadBalancer" || selector["openkubes.io/execution-id"] != runID ||
				annotations["openkubes.io/activation-digest"] != receipt.ActivationDigest ||
				annotations["openkubes.io/public-endpoint-digest"] != receipt.PublicEndpointDigest {
				return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector Service semantics differ")
			}
		case "NetworkPolicy":
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			labels, _ := selector["matchLabels"].(map[string]any)
			if name != runID || labels["openkubes.io/execution-id"] != runID {
				return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector NetworkPolicy semantics differ")
			}
		case "Job":
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if name != runID || spec["backoffLimit"] != 0 || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" ||
				podSpec["automountServiceAccountToken"] != false || annotations["openkubes.io/activation-digest"] != receipt.ActivationDigest ||
				annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest || annotations["openkubes.io/runtime-binding-digest"] != receipt.RuntimeBindingDigest ||
				annotations["openkubes.io/public-endpoint-digest"] != receipt.PublicEndpointDigest {
				return ObservabilityCollectorRuntimeInstallationPlan{}, errors.New("observability collector Job semantics differ")
			}
		}
	}
	return ObservabilityCollectorRuntimeInstallationPlan{
		Format: ObservabilityCollectorRuntimeInstallationPlanFormat, State: "VERIFIED", RunID: runID,
		PackageDigest: receipt.PackageDigest, ManifestDigest: receipt.ManifestDigest, RuntimeBindingDigest: receipt.RuntimeBindingDigest,
		TargetIdentityDigest: targetIdentity, Authority: targetIdentity,
		Prerequisites: []FullRunExecutionActivationPrerequisite{
			{Order: 1, APIVersion: "v1", Kind: "ServiceAccount", Namespace: submissionStageInputNamespace, Name: "ok147-contract-executor-runtime", Method: http.MethodGet,
				ObjectPath: "/api/v1/namespaces/" + submissionStageInputNamespace + "/serviceaccounts/ok147-contract-executor-runtime", ExpectState: "PRESENT_EXACT_RUNTIME"},
		},
		Creates: creates, MutationAllowed: false,
	}, nil
}

func observabilityCollectorCreatePaths(apiVersion, kind, namespace, name string) (string, string, error) {
	var collection string
	switch {
	case apiVersion == "v1" && kind == "Secret":
		collection = "/api/v1/namespaces/" + namespace + "/secrets"
	case apiVersion == "v1" && kind == "Service":
		collection = "/api/v1/namespaces/" + namespace + "/services"
	default:
		return postRuntimeActivationCreatePaths(apiVersion, kind, namespace, name)
	}
	return collection, collection + "/" + name, nil
}

func prepareObservabilityCollectorRuntimeInstallation(packaged VerifiedObservabilityCollectorRuntimePackage) (ObservabilityCollectorRuntimeInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		return ObservabilityCollectorRuntimeInstallationPlan{}, nil, err
	}
	values, err := decodeFullRunActivationObjects(packaged.raw, len(plan.Creates))
	if err != nil {
		return ObservabilityCollectorRuntimeInstallationPlan{}, nil, err
	}
	objects := make([]submissionStageInstallObject, 0, len(values))
	for index, value := range values {
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return ObservabilityCollectorRuntimeInstallationPlan{}, nil, errors.New("observability collector object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	return plan, objects, nil
}

type KubernetesObservabilityCollectorRuntimeLauncher struct {
	mu       sync.Mutex
	used     bool
	endpoint *url.URL
	token    string
	client   *http.Client
	plan     ObservabilityCollectorRuntimeInstallationPlan
	objects  []submissionStageInstallObject
}

func OpenKubernetesObservabilityCollectorRuntimeLauncher(config ObservabilityCollectorRuntimeLauncherConfig, packaged VerifiedObservabilityCollectorRuntimePackage) (*KubernetesObservabilityCollectorRuntimeLauncher, error) {
	receipt, err := packaged.Receipt()
	if err != nil || receipt.PackageDigest != config.ExpectedPackageDigest {
		return nil, errors.New("observability collector package differs from expected identity")
	}
	plan, _, err := prepareObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil || config.Authority.AuthorityIdentity != plan.Authority || !stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("observability collector authority differs from target identity")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil {
		return nil, errors.New("observability collector endpoint is invalid")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded observability collector credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("observability collector CA differs from bound identity")
	}
	return newKubernetesObservabilityCollectorRuntimeLauncher(submissionStageInstallerClientConfig{
		Endpoint: endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity, Client: client,
	}, packaged)
}

func newKubernetesObservabilityCollectorRuntimeLauncher(config submissionStageInstallerClientConfig, packaged VerifiedObservabilityCollectorRuntimePackage) (*KubernetesObservabilityCollectorRuntimeLauncher, error) {
	plan, objects, err := prepareObservabilityCollectorRuntimeInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("observability collector authority differs from target identity")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("observability collector Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("observability collector Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil {
		return nil, errors.New("observability collector credential or client is invalid")
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesObservabilityCollectorRuntimeLauncher{endpoint: endpoint, token: config.BearerToken, client: &client, plan: plan, objects: objects}, nil
}

func (launcher *KubernetesObservabilityCollectorRuntimeLauncher) Launch(ctx context.Context) (ObservabilityCollectorRuntimeLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil {
		return receipt, errors.New("observability collector launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopObservabilityCollectorRuntime(receipt, "STOPPED_ZERO_WRITE", errors.New("observability collector launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()
	for _, prerequisite := range launcher.plan.Prerequisites {
		raw, status, err := launcher.request(ctx, http.MethodGet, prerequisite.ObjectPath, nil)
		if err != nil || status != http.StatusOK || !fullRunActivationPrerequisiteMatches(raw, prerequisite) {
			if err == nil {
				err = errors.New("observability collector prerequisite differs; zero-write preflight stopped")
			}
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_ZERO_WRITE", err)
		}
	}
	for _, object := range launcher.objects {
		_, status, err := launcher.request(ctx, http.MethodGet, object.plan.ObjectPath, nil)
		if err != nil {
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_ZERO_WRITE", err)
		}
		if status == http.StatusOK {
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_ZERO_WRITE", errors.New("observability collector object already exists; zero-write preflight stopped"))
		}
		if status != http.StatusNotFound {
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_ZERO_WRITE", fmt.Errorf("bounded observability collector GET returned HTTP %d", status))
		}
	}
	receipt.State = "ACTIVATING"
	for _, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
		if err != nil {
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", fmt.Errorf("bounded observability collector POST returned HTTP %d", status))
		}
		uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
		if err != nil {
			return stopObservabilityCollectorRuntime(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created observability collector object differs from verified package"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageInstalledObject{
			Order: object.plan.Order, APIVersion: object.plan.APIVersion, Kind: object.plan.Kind, Namespace: object.plan.Namespace,
			Name: object.plan.Name, ObjectDigest: object.plan.ObjectDigest, UIDDigest: digest.SHA256([]byte(uid)),
			ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "ACTIVATED"
	return receipt, nil
}

func (launcher *KubernetesObservabilityCollectorRuntimeLauncher) newReceipt() ObservabilityCollectorRuntimeLaunchReceipt {
	receipt := ObservabilityCollectorRuntimeLaunchReceipt{Format: ObservabilityCollectorRuntimeLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageInstalledObject{}}
	if launcher != nil {
		receipt.RunID, receipt.PackageDigest, receipt.ManifestDigest, receipt.RuntimeBindingDigest, receipt.TargetIdentityDigest, receipt.Authority =
			launcher.plan.RunID, launcher.plan.PackageDigest, launcher.plan.ManifestDigest, launcher.plan.RuntimeBindingDigest, launcher.plan.TargetIdentityDigest, launcher.plan.Authority
	}
	return receipt
}

func stopObservabilityCollectorRuntime(receipt ObservabilityCollectorRuntimeLaunchReceipt, state string, err error) (ObservabilityCollectorRuntimeLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (launcher *KubernetesObservabilityCollectorRuntimeLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded observability collector request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded observability collector %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded observability collector response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded observability collector response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}
