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

const AggregateEvidenceStageLaunchReceiptFormat = "ok147-aggregate-evidence-stage-launch-receipt/v1"

type AggregateEvidenceStageLauncherConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	Candidate               VerifiedAggregateEvidenceStageLaunchCandidate
	ExpectedCandidateDigest string
}

type AggregateEvidenceStageLaunchReceipt struct {
	Format                    string                        `json:"format"`
	StageID                   string                        `json:"stageId"`
	EvidencePackageDigest     string                        `json:"evidencePackageDigest"`
	CredentialPackageDigest   string                        `json:"credentialPackageDigest"`
	PrivateInputPackageDigest string                        `json:"privateInputPackageDigest"`
	RuntimeManifestDigest     string                        `json:"runtimeManifestDigest"`
	Authority                 string                        `json:"authority"`
	State                     string                        `json:"state"`
	MutationState             string                        `json:"mutationState"`
	Results                   []SubmissionStageLaunchResult `json:"results"`
}

// KubernetesAggregateEvidenceStageLauncher is a single-use, nine-create
// operation. It completes all ten exact GETs before its first POST. The
// durable runtime-binding Secret must already exist and has no create path.
type KubernetesAggregateEvidenceStageLauncher struct {
	mu            sync.Mutex
	used          bool
	endpoint      *url.URL
	token         string
	client        *http.Client
	clock         func() time.Time
	validUntil    time.Time
	plan          AggregateEvidenceStageLaunchPlan
	runtime       VerifiedAggregateEvidenceStageRuntimePrerequisite
	credentials   AggregateEvidenceStageCredentialPackageReceipt
	secrets       []submissionStageCredentialInstallObject
	publicObjects []submissionStageInstallObject
	privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage
}

// OpenKubernetesAggregateEvidenceStageLauncher opens the exact prepared API
// client and installer credential without performing an API request.
func OpenKubernetesAggregateEvidenceStageLauncher(config AggregateEvidenceStageLauncherConfig, packaged VerifiedAggregateEvidenceStagePackage, credentials VerifiedAggregateEvidenceStageCredentialPackage, privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage, runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) (*KubernetesAggregateEvidenceStageLauncher, error) {
	plan, err := PlanAggregateEvidenceStageLaunch(packaged, credentials, privateInputs, runtime)
	if err != nil {
		return nil, err
	}
	if err := verifyAggregateEvidenceStageLaunchCandidate(config.Candidate); err != nil {
		return nil, err
	}
	candidate := config.Candidate.receipt
	planRaw, err := json.Marshal(plan)
	if err != nil {
		return nil, errors.New("encode aggregate evidence launcher plan identity")
	}
	if config.ExpectedCandidateDigest != candidate.CandidateDigest || digest.SHA256(planRaw) != candidate.LaunchPlanDigest || plan.StageID != candidate.StageID || plan.Authority != candidate.Authority || plan.EvidencePackageDigest != candidate.EvidencePackageDigest || plan.CredentialPackageDigest != candidate.CredentialPackageDigest || plan.PrivateInputPackageDigest != candidate.PrivateInputPackageDigest || plan.RuntimeManifestDigest != candidate.RuntimeManifestDigest {
		return nil, errors.New("aggregate evidence launcher components differ from exact candidate")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != plan.Authority {
		return nil, errors.New("aggregate evidence launcher authority differs from verified management authority")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil || endpoint != config.Candidate.authorityEndpoint || config.Authority.CABundleDigest != candidate.CABundleDigest {
		return nil, errors.New("aggregate evidence launcher destination differs from exact candidate")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded aggregate evidence launcher credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest || digest.SHA256([]byte(token)) != config.Candidate.installerTokenDigest {
		return nil, errors.New("aggregate evidence launcher credential differs from bound identity")
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.ValidUntil)
	if err != nil {
		return nil, errors.New("aggregate evidence launch candidate validity is invalid")
	}
	return newKubernetesAggregateEvidenceStageLauncher(submissionStageLauncherClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock, ValidUntil: validUntil,
	}, packaged, credentials, privateInputs, runtime)
}

func newKubernetesAggregateEvidenceStageLauncher(config submissionStageLauncherClientConfig, packaged VerifiedAggregateEvidenceStagePackage, credentials VerifiedAggregateEvidenceStageCredentialPackage, privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage, runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) (*KubernetesAggregateEvidenceStageLauncher, error) {
	plan, err := PlanAggregateEvidenceStageLaunch(packaged, credentials, privateInputs, runtime)
	if err != nil {
		return nil, err
	}
	credentialReceipt, secrets, err := prepareAggregateEvidenceStageCredentialInstallation(credentials)
	if err != nil {
		return nil, err
	}
	_, publicObjects, err := prepareAggregateEvidenceStageInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if err := verifyAggregateEvidenceStagePrivateInputPackage(privateInputs); err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != plan.Authority {
		return nil, errors.New("aggregate evidence launcher authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("aggregate evidence launcher Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("aggregate evidence launcher Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("aggregate evidence launcher credential, client, or clock is invalid")
	}
	for _, secret := range secrets {
		if len(config.BearerToken) == len(secret.token) && subtle.ConstantTimeCompare([]byte(config.BearerToken), secret.token) == 1 {
			return nil, errors.New("aggregate evidence launcher and Job credentials must be distinct")
		}
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	runtime.raw = append([]byte(nil), runtime.raw...)
	privateInputs.objects = cloneAggregateEvidencePrivateInputObjects(privateInputs.objects)
	return &KubernetesAggregateEvidenceStageLauncher{
		endpoint: endpoint, token: config.BearerToken, client: &client, clock: config.Clock, validUntil: config.ValidUntil,
		plan: plan, runtime: runtime, credentials: credentialReceipt, secrets: secrets,
		publicObjects: publicObjects, privateInputs: privateInputs,
	}, nil
}

// Launch performs all ten GETs before deciding between already launched,
// allowed fresh launch, or zero-write stop. It has no update, patch, apply,
// delete, list, watch, retry or rollback path.
func (launcher *KubernetesAggregateEvidenceStageLauncher) Launch(ctx context.Context) (AggregateEvidenceStageLaunchReceipt, error) {
	receipt := launcher.newReceipt()
	if launcher == nil || launcher.client == nil || launcher.clock == nil {
		return receipt, errors.New("aggregate evidence launcher is required")
	}
	launcher.mu.Lock()
	if launcher.used {
		launcher.mu.Unlock()
		return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("aggregate evidence launcher is single-use"))
	}
	launcher.used = true
	launcher.mu.Unlock()

	now := launcher.clock().UTC()
	if !launcher.validUntil.IsZero() && now.After(launcher.validUntil) {
		return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("aggregate evidence launch candidate validity has expired"))
	}
	materializedAt, err := time.Parse(time.RFC3339, launcher.credentials.MaterializedAt)
	if err != nil || now.Before(materializedAt) {
		return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("aggregate evidence launch precedes credential materialization"))
	}
	for _, secret := range launcher.secrets {
		if secret.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("aggregate evidence credential has insufficient remaining lifetime"))
		}
	}

	existing := make(map[int]SubmissionStageLaunchResult, len(launcher.plan.Preflights))
	for _, preflight := range launcher.plan.Preflights {
		raw, status, err := launcher.request(ctx, http.MethodGet, preflight.ObjectPath, nil)
		if err != nil {
			return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			result, err := launcher.verifyExisting(preflight, raw)
			if err != nil {
				return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
			}
			existing[preflight.Order] = result
		default:
			return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
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
	privateRuntimeResult, privateRuntimeExists := existing[2]
	if !privateRuntimeExists || len(existing) != 1 && !(len(existing) == 2 && runtimeExists) {
		return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("aggregate evidence launch requires exact runtime binding and no other partial state"))
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
	receipt.Results = append(receipt.Results, privateRuntimeResult)
	for index := 0; index < 2; index++ {
		result, err := launcher.createPublic(ctx, index+3, "stage-prerequisites", launcher.publicObjects[index])
		if err != nil {
			return launcher.stopAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index, secret := range launcher.secrets {
		result, err := launcher.createCredential(ctx, index+5, secret)
		if err != nil {
			return launcher.stopAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	result, err := launcher.createPrivate(ctx, 9, "private-capability", launcher.privateInputs.objects[1])
	if err != nil {
		return launcher.stopAfterAttempt(receipt, err)
	}
	receipt.MutationState = "ATTEMPTED"
	receipt.Results = append(receipt.Results, result)
	result, err = launcher.createPublic(ctx, 10, "job", launcher.publicObjects[2])
	if err != nil {
		return launcher.stopAfterAttempt(receipt, err)
	}
	receipt.MutationState = "ATTEMPTED"
	receipt.Results = append(receipt.Results, result)
	receipt.State = "LAUNCHED"
	return receipt, nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) verifyExisting(preflight SubmissionStageLaunchPreflight, raw []byte) (SubmissionStageLaunchResult, error) {
	var uid, resourceVersion string
	var err error
	switch preflight.Phase {
	case "runtime":
		uid, resourceVersion, err = verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	case "private-runtime":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.privateInstallObject(0, preflight))
	case "stage-prerequisites":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.publicObjects[preflight.Order-3])
	case "credentials":
		uid, resourceVersion, err = verifySubmissionStageCredentialCreatedObject(raw, launcher.secrets[preflight.Order-5])
	case "private-capability":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.privateInstallObject(1, preflight))
	case "job":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, launcher.publicObjects[2])
	default:
		return SubmissionStageLaunchResult{}, errors.New("aggregate evidence preflight phase is invalid")
	}
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("existing aggregate evidence object differs from verified plan")
	}
	return aggregateEvidenceLaunchResult(preflight.Order, preflight.Phase, preflight.APIVersion, preflight.Kind, preflight.Namespace, preflight.Name, preflight.ObjectDigest, "EXISTING_VERIFIED", uid, resourceVersion), nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) privateInstallObject(index int, preflight SubmissionStageLaunchPreflight) submissionStageInstallObject {
	return submissionStageInstallObject{plan: SubmissionStageCreatePlan{
		APIVersion: preflight.APIVersion, Kind: preflight.Kind, Namespace: preflight.Namespace,
		Name: preflight.Name, ObjectDigest: preflight.ObjectDigest,
	}, raw: launcher.privateInputs.objects[index].raw}
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) createRuntime(ctx context.Context) (SubmissionStageLaunchResult, error) {
	create := launcher.plan.Creates[0]
	raw, status, err := launcher.request(ctx, http.MethodPost, create.CollectionPath, launcher.runtime.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageRuntimeObject(raw, launcher.runtime.raw)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created aggregate evidence runtime differs")
	}
	return aggregateEvidenceLaunchResult(1, "runtime", "v1", "ServiceAccount", create.Namespace, create.Name, create.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) createCredential(ctx context.Context, order int, secret submissionStageCredentialInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, secret.collectionPath, secret.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCredentialCreatedObject(raw, secret)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created aggregate evidence credential differs")
	}
	return aggregateEvidenceLaunchResult(order, "credentials", "v1", "Secret", submissionStageInputNamespace, secret.name, secret.objectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) createPublic(ctx context.Context, order int, phase string, object submissionStageInstallObject) (SubmissionStageLaunchResult, error) {
	return launcher.createInstallObject(ctx, order, phase, object)
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) createPrivate(ctx context.Context, order int, phase string, private aggregateEvidenceStagePrivateInputObject) (SubmissionStageLaunchResult, error) {
	create := launcher.plan.Creates[order-2]
	return launcher.createInstallObject(ctx, order, phase, submissionStageInstallObject{plan: SubmissionStageCreatePlan{
		APIVersion: create.APIVersion, Kind: create.Kind, Namespace: create.Namespace, Name: create.Name,
		CollectionPath: create.CollectionPath, ObjectDigest: create.ObjectDigest,
	}, raw: private.raw})
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) createInstallObject(ctx context.Context, order int, phase string, object submissionStageInstallObject) (SubmissionStageLaunchResult, error) {
	raw, status, err := launcher.request(ctx, http.MethodPost, object.plan.CollectionPath, object.raw)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	uid, resourceVersion, err := verifySubmissionStageCreatedObject(raw, object)
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created aggregate evidence object differs")
	}
	return aggregateEvidenceLaunchResult(order, phase, object.plan.APIVersion, object.plan.Kind, object.plan.Namespace, object.plan.Name, object.plan.ObjectDigest, "CREATED", uid, resourceVersion), nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) stopAfterAttempt(receipt AggregateEvidenceStageLaunchReceipt, err error) (AggregateEvidenceStageLaunchReceipt, error) {
	receipt.MutationState = "ATTEMPTED_UNKNOWN"
	return stopAggregateEvidenceStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *launcher.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded aggregate evidence launch request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+launcher.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := launcher.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded aggregate evidence launch %s failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded aggregate evidence response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded aggregate evidence response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func (launcher *KubernetesAggregateEvidenceStageLauncher) newReceipt() AggregateEvidenceStageLaunchReceipt {
	receipt := AggregateEvidenceStageLaunchReceipt{Format: AggregateEvidenceStageLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{}}
	if launcher != nil {
		receipt.StageID, receipt.Authority = launcher.plan.StageID, launcher.plan.Authority
		receipt.EvidencePackageDigest, receipt.CredentialPackageDigest = launcher.plan.EvidencePackageDigest, launcher.plan.CredentialPackageDigest
		receipt.PrivateInputPackageDigest, receipt.RuntimeManifestDigest = launcher.plan.PrivateInputPackageDigest, launcher.plan.RuntimeManifestDigest
	}
	return receipt
}

func stopAggregateEvidenceStageLaunch(receipt AggregateEvidenceStageLaunchReceipt, state string, err error) (AggregateEvidenceStageLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}

func aggregateEvidenceLaunchResult(order int, phase, apiVersion, kind, namespace, name, objectDigest, state, uid, resourceVersion string) SubmissionStageLaunchResult {
	return SubmissionStageLaunchResult{
		Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
		ObjectDigest: objectDigest, ObjectState: state, UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
	}
}
