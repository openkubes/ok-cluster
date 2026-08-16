package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
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

const SubmissionStageLaunchReceiptFormat = "ok147-submission-stage-launch-receipt/v1"

type SubmissionStageLauncherConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	Candidate               VerifiedSubmissionStageLaunchCandidate
	ExpectedCandidateDigest string
}

type SubmissionStageLaunchResult struct {
	Order                 int    `json:"order"`
	Phase                 string `json:"phase"`
	APIVersion            string `json:"apiVersion"`
	Kind                  string `json:"kind"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	ObjectDigest          string `json:"objectDigest"`
	ObjectState           string `json:"objectState"`
	UIDDigest             string `json:"uidDigest"`
	ResourceVersionDigest string `json:"resourceVersionDigest"`
}

// SubmissionStageLaunchReceipt contains only the verified created prefix and
// redaction-safe runtime identity. It never contains object bodies or tokens.
type SubmissionStageLaunchReceipt struct {
	Format                  string                        `json:"format"`
	StageID                 string                        `json:"stageId"`
	StagePackageDigest      string                        `json:"stagePackageDigest"`
	CredentialPackageDigest string                        `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string                        `json:"runtimeManifestDigest"`
	Authority               string                        `json:"authority"`
	State                   string                        `json:"state"`
	MutationState           string                        `json:"mutationState"`
	Results                 []SubmissionStageLaunchResult `json:"results"`
}

// KubernetesSubmissionStageLauncher is a single-use six-object operation. It
// completes every preflight before it can issue its first create request.
type KubernetesSubmissionStageLauncher struct {
	mu          sync.Mutex
	used        bool
	endpoint    *url.URL
	token       string
	client      *http.Client
	clock       func() time.Time
	validUntil  time.Time
	plan        SubmissionStageLaunchPlan
	runtime     VerifiedSubmissionStageRuntimePrerequisite
	credentials SubmissionStageCredentialPackageReceipt
	secrets     []submissionStageCredentialInstallObject
	objects     []submissionStageInstallObject
}

type submissionStageLauncherClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
	Clock             func() time.Time
	ValidUntil        time.Time
}

// OpenKubernetesSubmissionStageLauncher opens one exact management-plane
// client for one coherent launch. It performs no API request.
func OpenKubernetesSubmissionStageLauncher(config SubmissionStageLauncherConfig, packaged VerifiedSubmissionStagePackage, credentials VerifiedSubmissionStageCredentialPackage, runtime VerifiedSubmissionStageRuntimePrerequisite) (*KubernetesSubmissionStageLauncher, error) {
	plan, err := PlanSubmissionStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	if err := verifySubmissionStageLaunchCandidate(config.Candidate); err != nil {
		return nil, err
	}
	candidate := config.Candidate.receipt
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return nil, errors.New("encode stage launcher plan identity")
	}
	if config.ExpectedCandidateDigest != candidate.CandidateDigest || digest.SHA256(planRaw) != candidate.LaunchPlanDigest || plan.StageID != candidate.StageID || plan.Authority != candidate.Authority || plan.StagePackageDigest != candidate.StagePackageDigest || plan.CredentialPackageDigest != candidate.CredentialPackageDigest || plan.RuntimeManifestDigest != candidate.RuntimeManifestDigest {
		return nil, errors.New("stage launcher components differ from exact launch candidate")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != packaged.installationAuthority {
		return nil, errors.New("stage launcher authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil || endpoint != config.Candidate.authorityEndpoint || config.Authority.CABundleDigest != candidate.CABundleDigest {
		return nil, errors.New("stage launcher destination differs from exact launch candidate")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("stage launcher CA identity is required")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded stage launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest || digest.SHA256([]byte(token)) != config.Candidate.installerTokenDigest {
		return nil, errors.New("stage launcher credential differs from bound identity")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.ValidUntil)
	if err != nil {
		return nil, errors.New("stage launcher candidate validity is invalid")
	}
	return newKubernetesSubmissionStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock, ValidUntil: validUntil,
	}, packaged, credentials, runtime)
}

func newKubernetesSubmissionStageLauncher(config submissionStageLauncherClientConfig, packaged VerifiedSubmissionStagePackage, credentials VerifiedSubmissionStageCredentialPackage, runtime VerifiedSubmissionStageRuntimePrerequisite) (*KubernetesSubmissionStageLauncher, error) {
	plan, err := PlanSubmissionStageLaunch(packaged, credentials, runtime)
	if err != nil {
		return nil, err
	}
	credentialReceipt, secrets, err := prepareSubmissionStageCredentialInstallation(credentials)
	if err != nil {
		return nil, err
	}
	_, objects, err := prepareSubmissionStageInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("stage launcher authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("stage launcher Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("stage launcher Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("stage launcher Kubernetes credential, client, or clock is invalid")
	}
	for _, secret := range secrets {
		if len(config.BearerToken) == len(secret.token) && subtle.ConstantTimeCompare([]byte(config.BearerToken), secret.token) == 1 {
			return nil, errors.New("stage launcher and Job credentials must be distinct")
		}
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	runtime.raw = append([]byte(nil), runtime.raw...)
	return &KubernetesSubmissionStageLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, clock: config.Clock, validUntil: config.ValidUntil,
		plan: plan, runtime: runtime, credentials: credentialReceipt, secrets: secrets, objects: objects,
	}, nil
}

// Launch performs the complete six-object preflight and only then creates the
// absent runtime, both Secrets and the three stage objects in fixed order. It
// has no update, patch, apply, delete, list, watch, retry or rollback path.
func (launcher *KubernetesSubmissionStageLauncher) Launch(ctx context.Context) (SubmissionStageLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil || launcher.clock == nil {
		return receipt, errors.New("stage launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("stage launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	now := launcher.clock().UTC()
	if !launcher.validUntil.IsZero() && now.After(launcher.validUntil) {
		return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("stage launch candidate validity has expired"))
	}
	materializedAt, err := time.Parse(time.RFC3339, launcher.credentials.MaterializedAt)
	if err != nil || now.Before(materializedAt) {
		return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("stage launch time precedes credential materialization"))
	}
	for _, secret := range launcher.secrets {
		if secret.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("stage launch credential has insufficient remaining lifetime"))
		}
	}

	runtimeExists := false
	runtimeUID, runtimeResourceVersion := "", ""
	for _, preflight := range launcher.plan.Preflights {
		raw, status, err := launcher.request(ctx, http.MethodGet, preflight.ObjectPath, nil, preflight.ResponseMode)
		if err != nil {
			return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		if preflight.Order == 1 {
			switch status {
			case http.StatusNotFound:
			case http.StatusOK:
				runtimeUID, runtimeResourceVersion, err = verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
				if err != nil {
					return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("existing stage runtime differs from verified prerequisite"))
				}
				runtimeExists = true
			default:
				return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
			}
			continue
		}
		if status == http.StatusOK {
			return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("stage launch object already exists; global preflight stopped"))
		}
		if status != http.StatusNotFound {
			return stopSubmissionStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
		}
	}

	receipt.State = "LAUNCHING"
	if runtimeExists {
		receipt.Results = append(receipt.Results, launcher.result(1, "runtime", "v1", "ServiceAccount", launcher.runtime.receipt.Namespace, launcher.runtime.receipt.Name, launcher.runtime.receipt.ObjectDigest, "EXISTING_VERIFIED", runtimeUID, runtimeResourceVersion))
	} else {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		result, err := launcher.createRuntime(ctx)
		if err != nil {
			return stopSubmissionStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index, secret := range launcher.secrets {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		result, err := launcher.createSecret(ctx, index+2, secret)
		if err != nil {
			return stopSubmissionStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index, object := range launcher.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		result, err := launcher.createStageObject(ctx, index+4, object)
		if err != nil {
			return stopSubmissionStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	receipt.State, receipt.MutationState = "LAUNCHED", "ATTEMPTED"
	return receipt, nil
}

func (launcher *KubernetesSubmissionStageLauncher) createRuntime(ctx context.Context) (SubmissionStageLaunchResult, error) {
	create := launcher.plan.Creates[0]
	raw, status, err := launcher.create(ctx, create.CollectionPath, launcher.runtime.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created stage runtime differs from verified prerequisite")
	}
	return launcher.result(1, "runtime", "v1", "ServiceAccount", create.Namespace, create.Name, create.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesSubmissionStageLauncher) createSecret(ctx context.Context, order int, secret submissionStageCredentialInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.create(ctx, secret.collectionPath, secret.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCredentialCreatedObject(raw, secret)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created stage credential differs from verified package")
	}
	return launcher.result(order, "credentials", "v1", "Secret", submissionStageInputNamespace, secret.name, secret.objectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesSubmissionStageLauncher) createStageObject(ctx context.Context, order int, object submissionStageInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.create(ctx, object.plan.CollectionPath, object.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created stage object differs from verified package")
	}
	return launcher.result(order, "stage-package", object.plan.APIVersion, object.plan.Kind, object.plan.Namespace, object.plan.Name, object.plan.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesSubmissionStageLauncher) create(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	return launcher.request(ctx, http.MethodPost, path, body, "FULL_OBJECT")
}

func (launcher *KubernetesSubmissionStageLauncher) request(ctx context.Context, method, path string, body []byte, responseMode string) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded stage launch request")
	}
	request.Header.Set("Accept", "application/json")
	if method == http.MethodGet && responseMode == "PARTIAL_OBJECT_METADATA" {
		request.Header.Set("Accept", partialObjectMetadataAccept)
	}
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded stage launch %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded stage launch response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded stage launch response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func (launcher *KubernetesSubmissionStageLauncher) newReceipt() SubmissionStageLaunchReceipt {
	receipt := SubmissionStageLaunchReceipt{Format: SubmissionStageLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{}}
	if launcher != nil {
		receipt.StageID, receipt.StagePackageDigest = launcher.plan.StageID, launcher.plan.StagePackageDigest
		receipt.CredentialPackageDigest, receipt.RuntimeManifestDigest = launcher.plan.CredentialPackageDigest, launcher.plan.RuntimeManifestDigest
		receipt.Authority = launcher.plan.Authority
	}
	return receipt
}

func (launcher *KubernetesSubmissionStageLauncher) result(order int, phase, apiVersion, kind, namespace, name, objectDigest, state, uid, resourceVersion string) SubmissionStageLaunchResult {
	return SubmissionStageLaunchResult{
		Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
		ObjectDigest: objectDigest, ObjectState: state, UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
	}
}

func stopSubmissionStageLaunch(receipt SubmissionStageLaunchReceipt, state string, err error) (SubmissionStageLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func submissionStageLaunchCreateError(status int, err error) error {
	if err != nil {
		return err
	}
	return submissionStageLaunchStatusError(http.MethodPost, status)
}

func submissionStageLaunchStatusError(method string, status int) error {
	return fmt.Errorf("bounded stage launch %s returned HTTP %d", method, status)
}
