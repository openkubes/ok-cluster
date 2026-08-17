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
)

const (
	SubmissionStageCredentialInstallationReceiptFormat = "ok147-submission-stage-credential-installation-receipt/v1"
	partialObjectMetadataAccept                        = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
)

type SubmissionStageCredentialInstallerConfig struct {
	Authority KubernetesAuthorityConfig
	Clock     func() time.Time
}

type SubmissionStageInstalledCredential struct {
	Order                 int    `json:"order"`
	Role                  string `json:"role"`
	Authority             string `json:"authority"`
	Namespace             string `json:"namespace"`
	Name                  string `json:"name"`
	ObjectDigest          string `json:"objectDigest"`
	UIDDigest             string `json:"uidDigest"`
	ResourceVersionDigest string `json:"resourceVersionDigest"`
	State                 string `json:"state"`
}

type SubmissionStageCredentialInstallationReceipt struct {
	Format                  string                               `json:"format"`
	StageID                 string                               `json:"stageId"`
	StagePackageDigest      string                               `json:"stagePackageDigest"`
	CredentialPackageDigest string                               `json:"credentialPackageDigest"`
	Authority               string                               `json:"authority"`
	State                   string                               `json:"state"`
	MutationState           string                               `json:"mutationState"`
	Results                 []SubmissionStageInstalledCredential `json:"results"`
}

type submissionStageCredentialInstallObject struct {
	order          int
	role           string
	authority      string
	name           string
	objectPath     string
	collectionPath string
	objectDigest   string
	expiresAt      time.Time
	raw            []byte
	token          []byte
}

type KubernetesSubmissionStageCredentialInstaller struct {
	mu        sync.Mutex
	used      bool
	endpoint  *url.URL
	token     string
	client    *http.Client
	clock     func() time.Time
	authority string
	receipt   SubmissionStageCredentialPackageReceipt
	objects   []submissionStageCredentialInstallObject
}

type submissionStageCredentialInstallerClientConfig struct {
	Endpoint          string
	BearerToken       string
	AuthorityIdentity string
	Client            *http.Client
	Clock             func() time.Time
}

// OpenKubernetesSubmissionStageCredentialInstaller opens the separately
// credentialed management-plane writer for exactly one private two-Secret
// package. It performs no API request.
func OpenKubernetesSubmissionStageCredentialInstaller(config SubmissionStageCredentialInstallerConfig, packaged VerifiedSubmissionStageCredentialPackage) (*KubernetesSubmissionStageCredentialInstaller, error) {
	if _, _, err := prepareSubmissionStageCredentialInstallation(packaged); err != nil {
		return nil, err
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != packaged.installationAuthority {
		return nil, errors.New("stage credential installer authority differs from verified management authority")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(config.Authority.CABundleDigest) {
		return nil, errors.New("stage credential installer CA identity is required")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded stage credential installer credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest {
		return nil, errors.New("stage credential installer CA differs from bound identity")
	}
	return newKubernetesSubmissionStageCredentialInstaller(submissionStageCredentialInstallerClientConfig{
		Endpoint: config.Authority.Endpoint, BearerToken: token, AuthorityIdentity: config.Authority.AuthorityIdentity,
		Client: client, Clock: config.Clock,
	}, packaged)
}

func newKubernetesSubmissionStageCredentialInstaller(config submissionStageCredentialInstallerClientConfig, packaged VerifiedSubmissionStageCredentialPackage) (*KubernetesSubmissionStageCredentialInstaller, error) {
	receipt, objects, err := prepareSubmissionStageCredentialInstallation(packaged)
	if err != nil {
		return nil, err
	}
	if config.AuthorityIdentity == "" || config.AuthorityIdentity != packaged.installationAuthority {
		return nil, errors.New("stage credential installer authority differs from verified management authority")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Port() == "" || net.ParseIP(endpoint.Hostname()) == nil {
		return nil, errors.New("stage credential installer Kubernetes endpoint is invalid")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.Hostname() == "127.0.0.1") {
		return nil, errors.New("stage credential installer Kubernetes endpoint must use HTTPS")
	}
	if config.BearerToken == "" || strings.TrimSpace(config.BearerToken) != config.BearerToken || strings.ContainsAny(config.BearerToken, "\r\n") || config.Client == nil || config.Clock == nil {
		return nil, errors.New("stage credential installer Kubernetes credential, client, or clock is invalid")
	}
	for _, object := range objects {
		if len(config.BearerToken) == len(object.token) && subtle.ConstantTimeCompare([]byte(config.BearerToken), object.token) == 1 {
			return nil, errors.New("stage credential installer and Job credentials must be distinct")
		}
	}
	client := *config.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 {
		client.Timeout = 15 * time.Second
	}
	endpoint.Path, endpoint.RawPath = "", ""
	return &KubernetesSubmissionStageCredentialInstaller{
		endpoint: endpoint, token: config.BearerToken, client: &client, clock: config.Clock,
		authority: config.AuthorityIdentity, receipt: receipt, objects: objects,
	}, nil
}

// Install performs both exact absence GETs before the first Secret POST. It
// never adopts, returns, updates, patches, deletes, lists, watches or retries
// a Secret. Expired or nearly expired credentials stop locally with zero writes.
func (installer *KubernetesSubmissionStageCredentialInstaller) Install(ctx context.Context) (SubmissionStageCredentialInstallationReceipt, error) {
	receipt := installer.newReceipt()
	if installer == nil || installer.client == nil || installer.clock == nil {
		return receipt, errors.New("stage credential installer is required")
	}
	installer.mu.Lock()
	if installer.used {
		installer.mu.Unlock()
		return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage credential installer is single-use"))
	}
	installer.used = true
	installer.mu.Unlock()

	now := installer.clock().UTC()
	materializedAt, err := time.Parse(time.RFC3339, installer.receipt.MaterializedAt)
	if err != nil || now.Before(materializedAt) {
		return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage credential installation time precedes verified materialization"))
	}
	for _, object := range installer.objects {
		if object.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage credential has insufficient remaining lifetime"))
		}
	}
	for _, object := range installer.objects {
		_, status, err := installer.request(ctx, http.MethodGet, object.objectPath, nil)
		if err != nil {
			return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", errors.New("stage credential Secret already exists; zero-write preflight stopped"))
		default:
			return stoppedStageCredentialInstallation(receipt, "STOPPED_ZERO_WRITE", stageCredentialInstallationStatusError(http.MethodGet, status))
		}
	}

	receipt.State = "CREATING"
	for _, object := range installer.objects {
		receipt.MutationState = "ATTEMPTED_UNKNOWN"
		raw, status, err := installer.request(ctx, http.MethodPost, object.collectionPath, object.raw)
		if err != nil {
			return stoppedStageCredentialInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
		}
		if status != http.StatusCreated {
			receipt.MutationState = "ATTEMPTED"
			return stoppedStageCredentialInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", stageCredentialInstallationStatusError(http.MethodPost, status))
		}
		uid, resourceVersion, err := verifySubmissionStageCredentialCreatedObject(raw, object)
		if err != nil {
			return stoppedStageCredentialInstallation(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", errors.New("created stage credential differs from verified package"))
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, SubmissionStageInstalledCredential{
			Order: object.order, Role: object.role, Authority: object.authority, Namespace: submissionStageInputNamespace,
			Name: object.name, ObjectDigest: object.objectDigest, UIDDigest: digest.SHA256([]byte(uid)),
			ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)), State: "CREATED",
		})
	}
	receipt.State = "INSTALLED"
	return receipt, nil
}

func (installer *KubernetesSubmissionStageCredentialInstaller) newReceipt() SubmissionStageCredentialInstallationReceipt {
	receipt := SubmissionStageCredentialInstallationReceipt{
		Format: SubmissionStageCredentialInstallationReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED",
		Results: []SubmissionStageInstalledCredential{},
	}
	if installer != nil {
		receipt.StageID = installer.receipt.StageID
		receipt.StagePackageDigest = installer.receipt.StagePackageDigest
		receipt.CredentialPackageDigest = installer.receipt.PackageDigest
		receipt.Authority = installer.authority
	}
	return receipt
}

func stoppedStageCredentialInstallation(receipt SubmissionStageCredentialInstallationReceipt, state string, err error) (SubmissionStageCredentialInstallationReceipt, error) {
	receipt.State = state
	return receipt, err
}

func (installer *KubernetesSubmissionStageCredentialInstaller) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *installer.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded stage credential request")
	}
	request.Header.Set("Accept", "application/json")
	if method == http.MethodGet {
		request.Header.Set("Accept", partialObjectMetadataAccept)
	}
	request.Header.Set("Authorization", "Bearer "+installer.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := installer.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded stage credential %s request failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded stage credential response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded stage credential response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func prepareSubmissionStageCredentialInstallation(packaged VerifiedSubmissionStageCredentialPackage) (SubmissionStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if !packaged.verified || packaged.receipt.Format != SubmissionStageCredentialPackageFormat || packaged.receipt.State != "VERIFIED" || packaged.installationAuthority == "" || len(packaged.objects) != 2 || len(packaged.receipt.Credentials) != 2 {
		return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential package was not produced by verification")
	}
	identity, err := json.Marshal(submissionStageCredentialPackageIdentity{
		StagePackageDigest: packaged.receipt.StagePackageDigest, InstallationAuthority: packaged.receipt.InstallationAuthority,
		MaterializedAt: packaged.receipt.MaterializedAt,
		Credentials:    packaged.receipt.Credentials,
	})
	if err != nil || digest.SHA256(identity) != packaged.receipt.PackageDigest || !stageReceiptPrefixDigestPattern.MatchString(packaged.receipt.StagePackageDigest) || packaged.receipt.InstallationAuthority != packaged.installationAuthority {
		return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential package identity changed after verification")
	}
	if _, err := time.Parse(time.RFC3339, packaged.receipt.MaterializedAt); err != nil {
		return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential package materialization time is invalid")
	}
	expectedRoles := []string{"ledger", "authority"}
	objects := make([]submissionStageCredentialInstallObject, 0, 2)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		if private.role != expectedRoles[index] || private.role != public.Role || private.authority != public.Authority || private.name != public.Name || public.Namespace != submissionStageInputNamespace || digest.SHA256(private.raw) != public.ObjectDigest {
			return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential object identity changed after verification")
		}
		var secret map[string]any
		if err := json.Unmarshal(private.raw, &secret); err != nil {
			return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != 2 {
			return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential Secret semantics changed after verification")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return SubmissionStageCredentialPackageReceipt{}, nil, errors.New("stage credential Secret data changed after verification")
		}
		collectionPath := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
		objects = append(objects, submissionStageCredentialInstallObject{
			order: index + 1, role: private.role, authority: private.authority, name: private.name,
			objectPath: collectionPath + "/" + private.name, collectionPath: collectionPath,
			objectDigest: public.ObjectDigest, expiresAt: expiresAt, raw: append([]byte(nil), private.raw...), token: token,
		})
	}
	return packaged.receipt, objects, nil
}

func verifySubmissionStageCredentialCreatedObject(raw []byte, expected submissionStageCredentialInstallObject) (string, string, error) {
	observed, err := decodeCapabilityJSONObject(raw)
	if err != nil {
		return "", "", err
	}
	desired, err := decodeCapabilityJSONObject(expected.raw)
	if err != nil || !capabilitySubset(desired, observed) {
		return "", "", errors.New("observed Secret does not contain exact package fields")
	}
	metadata, _ := observed["metadata"].(map[string]any)
	uid, _ := metadata["uid"].(string)
	resourceVersion, _ := metadata["resourceVersion"].(string)
	if !runtimeInputUIDPattern.MatchString(uid) || !runtimeInputUIDPattern.MatchString(resourceVersion) {
		return "", "", errors.New("created Secret lacks bounded runtime identity")
	}
	return uid, resourceVersion, nil
}

func stageCredentialInstallationStatusError(method string, status int) error {
	return fmt.Errorf("bounded stage credential %s returned HTTP %d", method, status)
}
