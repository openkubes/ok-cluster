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

const EnablementStageLaunchReceiptFormat = "ok147-enablement-stage-launch-receipt/v1"

type EnablementStageLauncherConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	Candidate               VerifiedEnablementStageLaunchCandidate
	ExpectedCandidateDigest string
}

type EnablementStageLaunchReceipt struct {
	Format                  string                        `json:"format"`
	StageID                 string                        `json:"stageId"`
	EnablementPackageDigest string                        `json:"enablementPackageDigest"`
	CredentialPackageDigest string                        `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string                        `json:"runtimeManifestDigest"`
	Authority               string                        `json:"authority"`
	State                   string                        `json:"state"`
	MutationState           string                        `json:"mutationState"`
	Results                 []SubmissionStageLaunchResult `json:"results"`
}

// KubernetesEnablementStageLauncher is a single-use six-object create-only
// operation. It completes the global preflight before its first POST and has
// no update, patch, apply, delete, list, watch or retry path.
type KubernetesEnablementStageLauncher struct {
	mu          sync.Mutex
	used        bool
	endpoint    *url.URL
	token       string
	client      *http.Client
	clock       func() time.Time
	validUntil  time.Time
	plan        EnablementStageLaunchPlan
	runtime     VerifiedEnablementStageRuntimePrerequisite
	credentials EnablementStageCredentialPackageReceipt
	secrets     []submissionStageCredentialInstallObject
	objects     []submissionStageInstallObject
}

// OpenKubernetesEnablementStageLauncher opens one exact client from the
// prepared candidate and bounded installer credential. It performs no API
// request.
func OpenKubernetesEnablementStageLauncher(config EnablementStageLauncherConfig, packaged VerifiedEnablementStagePackage, credentials VerifiedEnablementStageCredentialPackage, runtime VerifiedEnablementStageRuntimePrerequisite) (*KubernetesEnablementStageLauncher, error) {
	plan, err := PlanEnablementStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	if err := verifyEnablementStageLaunchCandidate(config.Candidate); err != nil {
		return nil, err
	}
	candidate := config.Candidate.receipt
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return nil, errors.New("encode enablement launcher plan identity")
	}
	if config.ExpectedCandidateDigest != candidate.CandidateDigest || digest.SHA256(planRaw) != candidate.LaunchPlanDigest || plan.StageID != candidate.StageID || plan.Authority != candidate.Authority || plan.EnablementPackageDigest != candidate.EnablementPackageDigest || plan.CredentialPackageDigest != candidate.CredentialPackageDigest || plan.RuntimeManifestDigest != candidate.RuntimeManifestDigest {
		return nil, errors.New("enablement launcher components differ from exact candidate")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != plan.Authority {
		return nil, errors.New("enablement launcher authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil || endpoint != config.Candidate.authorityEndpoint || config.Authority.CABundleDigest != candidate.CABundleDigest {
		return nil, errors.New("enablement launcher destination differs from exact candidate")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded enablement launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest || digest.SHA256([]byte(token)) != config.Candidate.installerTokenDigest {
		return nil, errors.New("enablement launcher credential differs from bound identity")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.ValidUntil)
	if err != nil {
		return nil, errors.New("enablement launch candidate validity is invalid")
	}
	return newKubernetesEnablementStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock, ValidUntil: validUntil,
	}, packaged, credentials, runtime)
}

func newKubernetesEnablementStageLauncher(config submissionStageLauncherClientConfig, packaged VerifiedEnablementStagePackage, credentials VerifiedEnablementStageCredentialPackage, runtime VerifiedEnablementStageRuntimePrerequisite) (*KubernetesEnablementStageLauncher, error) {
	plan, err := PlanEnablementStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	credentialReceipt, secrets, err := prepareEnablementStageCredentialInstallation(credentials)
	if err != nil {
		return nil, err
	}
	_, objects, err := prepareEnablementStageInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("enablement launcher authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("enablement launcher Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("enablement launcher Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("enablement launcher credential, client, or clock is invalid")
	}
	for _, secret := range secrets {
		if len(config.BearerToken) == len(secret.token) && subtle.ConstantTimeCompare([]byte(config.BearerToken), secret.token) == 1 {
			return nil, errors.New("enablement launcher and Job credentials must be distinct")
		}
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	runtime.raw = append([]byte(nil), runtime.raw...)
	return &KubernetesEnablementStageLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, clock: config.Clock, validUntil: config.ValidUntil,
		plan: plan, runtime: runtime, credentials: credentialReceipt, secrets: secrets, objects: objects,
	}, nil
}

func (launcher *KubernetesEnablementStageLauncher) Launch(ctx context.Context) (EnablementStageLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil || launcher.clock == nil {
		return receipt, errors.New("enablement launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("enablement launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	now := launcher.clock().UTC()
	if !launcher.validUntil.IsZero() && now.After(launcher.validUntil) {
		return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("enablement launch candidate validity has expired"))
	}
	materializedAt, err := time.Parse(time.RFC3339, launcher.credentials.MaterializedAt)
	if err != nil || now.Before(materializedAt) {
		return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("enablement launch precedes credential materialization"))
	}
	for _, secret := range launcher.secrets {
		if secret.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("enablement credential has insufficient remaining lifetime"))
		}
	}

	existing := make(map[int]SubmissionStageLaunchResult, len(launcher.plan.Preflights))
	for _, preflight := range launcher.plan.Preflights {
		raw, status, err := launcher.request(ctx, http.MethodGet, preflight.ObjectPath, nil)
		if err != nil {
			return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			result, err := launcher.verifyExisting(preflight, raw)
			if err != nil {
				return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
			}
			existing[preflight.Order] = result
		default:
			return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
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
		return stopEnablementStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("enablement launch found exact partial state"))
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

func (launcher *KubernetesEnablementStageLauncher) verifyExisting(preflight SubmissionStageLaunchPreflight, raw []byte) (SubmissionStageLaunchResult, error) {
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
		return SubmissionStageLaunchResult{}, errors.New("enablement preflight phase is invalid")
	}
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("existing enablement object differs from verified plan")
	}
	return enablementLaunchResult(preflight.Order, preflight.Phase, preflight.APIVersion, preflight.Kind, preflight.Namespace, preflight.Name, preflight.ObjectDigest, "EXISTING_VERIFIED", uid, resourceVersion), nil
}

func (launcher *KubernetesEnablementStageLauncher) createRuntime(ctx context.Context) (SubmissionStageLaunchResult, error) {
	create := launcher.plan.Creates[0]
	raw, status, err := launcher.request(ctx, http.MethodPost, create.CollectionPath, launcher.runtime.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created enablement runtime differs")
	}
	return enablementLaunchResult(1, "runtime", "v1", "ServiceAccount", create.Namespace, create.Name, create.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesEnablementStageLauncher) createSecret(ctx context.Context, order int, secret submissionStageCredentialInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, secret.collectionPath, secret.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCredentialCreatedObject(raw, secret)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created enablement credential differs")
	}
	return enablementLaunchResult(order, "credentials", "v1", "Secret", submissionStageInputNamespace, secret.name, secret.objectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesEnablementStageLauncher) createObject(ctx context.Context, order int, phase string, object submissionStageInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created enablement object differs")
	}
	return enablementLaunchResult(order, phase, object.plan.APIVersion, object.plan.Kind, object.plan.Namespace, object.plan.Name, object.plan.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesEnablementStageLauncher) stopAfterAttempt(receipt EnablementStageLaunchReceipt, err error) (EnablementStageLaunchReceipt, error) {
	receipt.MutationState = "ATTEMPTED_UNKNOWN"
	return stopEnablementStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
}

func (launcher *KubernetesEnablementStageLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded enablement launch request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded enablement launch %s failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded enablement response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded enablement response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func (launcher *KubernetesEnablementStageLauncher) newReceipt() EnablementStageLaunchReceipt {
	receipt := EnablementStageLaunchReceipt{Format: EnablementStageLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{}}
	if launcher != nil {
		receipt.StageID, receipt.Authority = launcher.plan.StageID, launcher.plan.Authority
		receipt.EnablementPackageDigest, receipt.CredentialPackageDigest = launcher.plan.EnablementPackageDigest, launcher.plan.CredentialPackageDigest
		receipt.RuntimeManifestDigest = launcher.plan.RuntimeManifestDigest
	}
	return receipt
}

func stopEnablementStageLaunch(receipt EnablementStageLaunchReceipt, state string, err error) (EnablementStageLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func enablementLaunchResult(order int, phase, apiVersion, kind, namespace, name, objectDigest, state, uid, resourceVersion string) SubmissionStageLaunchResult {
	return SubmissionStageLaunchResult{
		Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
		ObjectDigest: objectDigest, ObjectState: state, UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
	}
}

func prepareEnablementStageInstallation(packaged VerifiedEnablementStagePackage) (EnablementStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanEnablementStageInstallation(packaged)
	if err != nil {
		return EnablementStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return EnablementStageInstallationPlan{}, nil, errors.New("decode enablement installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return EnablementStageInstallationPlan{}, nil, errors.New("enablement installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return EnablementStageInstallationPlan{}, nil, errors.New("enablement installation contains trailing object")
	}
	return plan, objects, nil
}

func prepareEnablementStageCredentialInstallation(packaged VerifiedEnablementStageCredentialPackage) (EnablementStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if err := verifyEnablementStageCredentialPackage(packaged); err != nil {
		return EnablementStageCredentialPackageReceipt{}, nil, err
	}
	objects := make([]submissionStageCredentialInstallObject, 0, 2)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		var secret map[string]any
		if err := json.Unmarshal(private.raw, &secret); err != nil {
			return EnablementStageCredentialPackageReceipt{}, nil, errors.New("enablement credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != 2 {
			return EnablementStageCredentialPackageReceipt{}, nil, errors.New("enablement credential Secret semantics changed")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return EnablementStageCredentialPackageReceipt{}, nil, errors.New("enablement credential Secret data changed")
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
