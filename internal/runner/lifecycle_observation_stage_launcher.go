package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
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
	"gopkg.in/yaml.v3"
)

const LifecycleObservationStageLaunchReceiptFormat = "ok147-lifecycle-observation-stage-launch-receipt/v1"

type LifecycleObservationStageLauncherConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	Candidate               VerifiedLifecycleObservationStageLaunchCandidate
	ExpectedCandidateDigest string
}

type LifecycleObservationStageLaunchReceipt struct {
	Format                   string                        `json:"format"`
	StageID                  string                        `json:"stageId"`
	ObservationPackageDigest string                        `json:"observationPackageDigest"`
	CredentialPackageDigest  string                        `json:"credentialPackageDigest"`
	RuntimeManifestDigest    string                        `json:"runtimeManifestDigest"`
	Authority                string                        `json:"authority"`
	State                    string                        `json:"state"`
	MutationState            string                        `json:"mutationState"`
	Results                  []SubmissionStageLaunchResult `json:"results"`
}

// KubernetesLifecycleObservationStageLauncher is a single-use six-object
// create-only operation. It completes the global preflight before its first
// POST and contains no update, patch, apply, delete, list, watch or retry path.
type KubernetesLifecycleObservationStageLauncher struct {
	mu          sync.Mutex
	used        bool
	endpoint    *url.URL
	token       string
	client      *http.Client
	clock       func() time.Time
	validUntil  time.Time
	plan        LifecycleObservationStageLaunchPlan
	runtime     VerifiedLifecycleObservationStageRuntimePrerequisite
	credentials LifecycleObservationStageCredentialPackageReceipt
	secrets     []submissionStageCredentialInstallObject
	objects     []submissionStageInstallObject
}

// OpenKubernetesLifecycleObservationStageLauncher opens one exact client from
// the prepared candidate and bounded installer credential. It performs no API
// request.
func OpenKubernetesLifecycleObservationStageLauncher(config LifecycleObservationStageLauncherConfig, packaged VerifiedLifecycleObservationStagePackage, credentials VerifiedLifecycleObservationStageCredentialPackage, runtime VerifiedLifecycleObservationStageRuntimePrerequisite) (*KubernetesLifecycleObservationStageLauncher, error) {
	plan, err := PlanLifecycleObservationStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	if err := verifyLifecycleObservationStageLaunchCandidate(config.Candidate); err != nil {
		return nil, err
	}
	candidate := config.Candidate.receipt
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return nil, errors.New("encode lifecycle observation launcher plan identity")
	}
	if config.ExpectedCandidateDigest != candidate.CandidateDigest || digest.SHA256(planRaw) != candidate.LaunchPlanDigest || plan.StageID != candidate.StageID || plan.Authority != candidate.Authority || plan.ObservationPackageDigest != candidate.ObservationPackageDigest || plan.CredentialPackageDigest != candidate.CredentialPackageDigest || plan.RuntimeManifestDigest != candidate.RuntimeManifestDigest {
		return nil, errors.New("lifecycle observation launcher components differ from exact candidate")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != plan.Authority {
		return nil, errors.New("lifecycle observation launcher authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil || endpoint != config.Candidate.authorityEndpoint || config.Authority.CABundleDigest != candidate.CABundleDigest {
		return nil, errors.New("lifecycle observation launcher destination differs from exact candidate")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded lifecycle observation launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest || digest.SHA256([]byte(token)) != config.Candidate.installerTokenDigest {
		return nil, errors.New("lifecycle observation launcher credential differs from bound identity")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.ValidUntil)
	if err != nil {
		return nil, errors.New("lifecycle observation launch candidate validity is invalid")
	}
	return newKubernetesLifecycleObservationStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock, ValidUntil: validUntil,
	}, packaged, credentials, runtime)
}

func newKubernetesLifecycleObservationStageLauncher(config submissionStageLauncherClientConfig, packaged VerifiedLifecycleObservationStagePackage, credentials VerifiedLifecycleObservationStageCredentialPackage, runtime VerifiedLifecycleObservationStageRuntimePrerequisite) (*KubernetesLifecycleObservationStageLauncher, error) {
	plan, err := PlanLifecycleObservationStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	credentialReceipt, secrets, err := prepareLifecycleObservationStageCredentialInstallation(credentials)
	if err != nil {
		return nil, err
	}
	_, objects, err := prepareLifecycleObservationStageInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("lifecycle observation launcher authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("lifecycle observation launcher Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("lifecycle observation launcher Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("lifecycle observation launcher credential, client, or clock is invalid")
	}
	for _, secret := range secrets {
		if len(config.BearerToken) == len(secret.token) && subtle.ConstantTimeCompare([]byte(config.BearerToken), secret.token) == 1 {
			return nil, errors.New("lifecycle observation launcher and Job credentials must be distinct")
		}
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	runtime.raw = append([]byte(nil), runtime.raw...)
	return &KubernetesLifecycleObservationStageLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, clock: config.Clock, validUntil: config.ValidUntil,
		plan: plan, runtime: runtime, credentials: credentialReceipt, secrets: secrets, objects: objects,
	}, nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) Launch(ctx context.Context) (LifecycleObservationStageLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil || launcher.clock == nil {
		return receipt, errors.New("lifecycle observation launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("lifecycle observation launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	now := launcher.clock().UTC()
	if !launcher.validUntil.IsZero() && now.After(launcher.validUntil) {
		return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("lifecycle observation launch candidate validity has expired"))
	}
	materializedAt, err := time.Parse(time.RFC3339, launcher.credentials.MaterializedAt)
	if err != nil || now.Before(materializedAt) {
		return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("lifecycle observation launch precedes credential materialization"))
	}
	for _, secret := range launcher.secrets {
		if secret.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("lifecycle observation credential has insufficient remaining lifetime"))
		}
	}

	existing := make(map[int]SubmissionStageLaunchResult, len(launcher.plan.Preflights))
	for _, preflight := range launcher.plan.Preflights {
		raw, status, err := launcher.request(ctx, http.MethodGet, preflight.ObjectPath, nil)
		if err != nil {
			return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			result, err := launcher.verifyExisting(preflight, raw)
			if err != nil {
				return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
			}
			existing[preflight.Order] = result
		default:
			return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
		}
	}
	if len(existing) == len(launcher.plan.Preflights) {
		receipt.State = "ALREADY_LAUNCHED"
		for order := 1; order <= len(launcher.plan.Preflights); order++ {
			receipt.Results = append(receipt.Results, existing[order])
		}
		return receipt, nil
	}
	runtimeResult, runtimeExists := existing[1]
	if len(existing) != 0 && !(len(existing) == 1 && runtimeExists) {
		return stopLifecycleObservationStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("lifecycle observation launch found exact partial state"))
	}

	receipt.State = "LAUNCHING"
	if runtimeExists {
		receipt.Results = append(receipt.Results, runtimeResult)
	} else {
		result, err := launcher.createRuntime(ctx)
		if err != nil {
			return launcher.stopAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index := 0; index < 2; index++ {
		result, err := launcher.createObject(ctx, index+2, "stage-prerequisites", launcher.objects[index])
		if err != nil {
			return launcher.stopAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index, secret := range launcher.secrets {
		result, err := launcher.createSecret(ctx, index+4, secret)
		if err != nil {
			return launcher.stopAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	result, err := launcher.createObject(ctx, 6, "job", launcher.objects[2])
	if err != nil {
		return launcher.stopAfterAttempt(receipt, err)
	}
	receipt.MutationState = "ATTEMPTED"
	receipt.Results = append(receipt.Results, result)
	receipt.State = "LAUNCHED"
	return receipt, nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) verifyExisting(preflight SubmissionStageLaunchPreflight, raw []byte) (SubmissionStageLaunchResult, error) {
	var uid, resourceVersion string
	var err error
	switch preflight.Phase {
	case "runtime":
		uid, resourceVersion, err = verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	case "stage-prerequisites":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.objects[preflight.Order-2])
	case "credentials":
		uid, resourceVersion, err = verifySubmissionStageCredentialCreatedObject(raw, launcher.secrets[preflight.Order-4])
	case "job":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.objects[2])
	default:
		return SubmissionStageLaunchResult{}, errors.New("lifecycle observation preflight phase is invalid")
	}
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("existing lifecycle observation object differs from verified plan")
	}
	return lifecycleObservationLaunchResult(preflight.Order, preflight.Phase, preflight.APIVersion, preflight.Kind, preflight.Namespace, preflight.Name, preflight.ObjectDigest, "EXISTING_VERIFIED", uid, resourceVersion), nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) createRuntime(ctx context.Context) (SubmissionStageLaunchResult, error) {
	create := launcher.plan.Creates[0]
	raw, status, err := launcher.request(ctx, http.MethodPost, create.CollectionPath, launcher.runtime.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created lifecycle observation runtime differs")
	}
	return lifecycleObservationLaunchResult(1, "runtime", "v1", "ServiceAccount", create.Namespace, create.Name, create.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) createSecret(ctx context.Context, order int, secret submissionStageCredentialInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, secret.collectionPath, secret.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCredentialCreatedObject(raw, secret)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created lifecycle observation credential differs")
	}
	return lifecycleObservationLaunchResult(order, "credentials", "v1", "Secret", submissionStageInputNamespace, secret.name, secret.objectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) createObject(ctx context.Context, order int, phase string, object submissionStageInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created lifecycle observation object differs")
	}
	return lifecycleObservationLaunchResult(order, phase, object.plan.APIVersion, object.plan.Kind, object.plan.Namespace, object.plan.Name, object.plan.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) stopAfterAttempt(receipt LifecycleObservationStageLaunchReceipt, err error) (LifecycleObservationStageLaunchReceipt, error) {
	receipt.MutationState = "ATTEMPTED_UNKNOWN"
	return stopLifecycleObservationStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
}

func (launcher *KubernetesLifecycleObservationStageLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded lifecycle observation launch request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded lifecycle observation launch %s failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded lifecycle observation response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded lifecycle observation response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func (launcher *KubernetesLifecycleObservationStageLauncher) newReceipt() LifecycleObservationStageLaunchReceipt {
	receipt := LifecycleObservationStageLaunchReceipt{Format: LifecycleObservationStageLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{}}
	if launcher != nil {
		receipt.StageID, receipt.Authority = launcher.plan.StageID, launcher.plan.Authority
		receipt.ObservationPackageDigest, receipt.CredentialPackageDigest = launcher.plan.ObservationPackageDigest, launcher.plan.CredentialPackageDigest
		receipt.RuntimeManifestDigest = launcher.plan.RuntimeManifestDigest
	}
	return receipt
}

func stopLifecycleObservationStageLaunch(receipt LifecycleObservationStageLaunchReceipt, state string, err error) (LifecycleObservationStageLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func lifecycleObservationLaunchResult(order int, phase, apiVersion, kind, namespace, name, objectDigest, state, uid, resourceVersion string) SubmissionStageLaunchResult {
	return SubmissionStageLaunchResult{
		Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
		ObjectDigest: objectDigest, ObjectState: state, UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
	}
}

func prepareLifecycleObservationStageInstallation(packaged VerifiedLifecycleObservationStagePackage) (LifecycleObservationStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanLifecycleObservationStageInstallation(packaged)
	if err != nil {
		return LifecycleObservationStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return LifecycleObservationStageInstallationPlan{}, nil, errors.New("decode lifecycle observation installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return LifecycleObservationStageInstallationPlan{}, nil, errors.New("lifecycle observation installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return LifecycleObservationStageInstallationPlan{}, nil, errors.New("lifecycle observation installation contains trailing object")
	}
	return plan, objects, nil
}

func prepareLifecycleObservationStageCredentialInstallation(packaged VerifiedLifecycleObservationStageCredentialPackage) (LifecycleObservationStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if err := verifyLifecycleObservationStageCredentialPackage(packaged); err != nil {
		return LifecycleObservationStageCredentialPackageReceipt{}, nil, err
	}
	objects := make([]submissionStageCredentialInstallObject, 0, 2)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		var secret map[string]any
		if err := json.Unmarshal(private.raw, &secret); err != nil {
			return LifecycleObservationStageCredentialPackageReceipt{}, nil, errors.New("lifecycle observation credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != 2 {
			return LifecycleObservationStageCredentialPackageReceipt{}, nil, errors.New("lifecycle observation credential Secret semantics changed")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return LifecycleObservationStageCredentialPackageReceipt{}, nil, errors.New("lifecycle observation credential Secret data changed")
		}
		collection := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
		objects = append(objects, submissionStageCredentialInstallObject{
			order: index + 4, role: private.role, authority: private.authority, name: private.name,
			objectPath: collection + "/" + private.name, collectionPath: collection,
			objectDigest: public.ObjectDigest, expiresAt: expiresAt, raw: append([]byte(nil), private.raw...), token: token,
		})
	}
	return packaged.receipt, objects, nil
}
