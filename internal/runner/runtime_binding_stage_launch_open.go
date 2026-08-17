package runner

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStageLaunchOpenReceiptFormat = "ok147-runtime-binding-stage-launch-open-receipt/v1"

type RuntimeBindingStageLaunchOpenConfig struct {
	Authority               KubernetesAuthorityConfig
	Clock                   func() time.Time
	ExpectedCandidateDigest string
}

type RuntimeBindingStageLaunchOpenReceipt struct {
	Format          string `json:"format"`
	State           string `json:"state"`
	StageID         string `json:"stageId"`
	Authority       string `json:"authority"`
	CandidateDigest string `json:"candidateDigest"`
	ValidUntil      string `json:"validUntil"`
	MutationAllowed bool   `json:"mutationAllowed"`
}

// OpenedRuntimeBindingStageLaunch retains the exact private launch material,
// bounded installer credential and API client for a later single-use launcher.
// It exposes only a redaction-safe receipt and performs no API request.
type OpenedRuntimeBindingStageLaunch struct {
	material   VerifiedRuntimeBindingStageLaunchMaterial
	endpoint   *url.URL
	token      string
	client     *http.Client
	clock      func() time.Time
	validUntil time.Time
	receipt    RuntimeBindingStageLaunchOpenReceipt
	verified   bool
}

// Open validates and consumes local installer material against the exact
// prepared candidate. It does not contact Kubernetes or authorize mutation.
func (material VerifiedRuntimeBindingStageLaunchMaterial) Open(config RuntimeBindingStageLaunchOpenConfig) (*OpenedRuntimeBindingStageLaunch, error) {
	if err := verifyRuntimeBindingStageLaunchMaterial(material); err != nil {
		return nil, err
	}
	candidate, err := material.candidate.Receipt()
	if err != nil {
		return nil, err
	}
	if config.ExpectedCandidateDigest == "" || config.ExpectedCandidateDigest != candidate.CandidateDigest {
		return nil, errors.New("runtime binding launch open requires the exact candidate digest")
	}
	if config.Authority.AuthorityIdentity == "" || config.Authority.AuthorityIdentity != candidate.Authority || config.Clock == nil {
		return nil, errors.New("runtime binding launch open authority or clock is invalid")
	}
	endpoint, err := normalizeSubmissionStageLaunchEndpoint(config.Authority.Endpoint)
	if err != nil || endpoint != material.candidate.authorityEndpoint || config.Authority.CABundleDigest != candidate.CABundleDigest {
		return nil, errors.New("runtime binding launch open destination differs from exact candidate")
	}
	token, ca, client, err := openBoundedKubernetesMaterial(config.Authority.TokenFile, config.Authority.CAFile)
	if err != nil {
		return nil, errors.New("open bounded runtime binding installer credential")
	}
	if digest.SHA256(ca) != config.Authority.CABundleDigest || digest.SHA256([]byte(token)) != material.candidate.installerTokenDigest {
		return nil, errors.New("runtime binding installer credential differs from bound identity")
	}
	_, secrets, err := prepareRuntimeBindingStageCredentialInstallation(material.credentials)
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets {
		if len(token) == len(secret.token) && subtle.ConstantTimeCompare([]byte(token), secret.token) == 1 {
			return nil, errors.New("runtime binding installer and Job credentials must be distinct")
		}
	}
	if _, _, err := prepareRuntimeBindingStageInstallation(material.packaged); err != nil {
		return nil, err
	}
	validUntil, err := time.Parse(time.RFC3339, candidate.ValidUntil)
	if err != nil {
		return nil, errors.New("runtime binding launch candidate validity is invalid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("runtime binding launch endpoint is invalid")
	}
	clientCopy := *client
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 15 * time.Second
	}
	receipt := RuntimeBindingStageLaunchOpenReceipt{
		Format: RuntimeBindingStageLaunchOpenReceiptFormat, State: "OPENED", StageID: candidate.StageID,
		Authority: candidate.Authority, CandidateDigest: candidate.CandidateDigest,
		ValidUntil: candidate.ValidUntil, MutationAllowed: false,
	}
	return &OpenedRuntimeBindingStageLaunch{
		material: material, endpoint: parsed, token: token, client: &clientCopy, clock: config.Clock,
		validUntil: validUntil, receipt: receipt, verified: true,
	}, nil
}

func (opened *OpenedRuntimeBindingStageLaunch) Receipt() (RuntimeBindingStageLaunchOpenReceipt, error) {
	if opened == nil || !opened.verified || opened.client == nil || opened.clock == nil || opened.endpoint == nil || opened.token == "" || opened.receipt.Format != RuntimeBindingStageLaunchOpenReceiptFormat || opened.receipt.State != "OPENED" || opened.receipt.MutationAllowed || opened.receipt.CandidateDigest != opened.material.receipt.CandidateDigest || opened.receipt.ValidUntil != opened.material.receipt.ValidUntil || opened.validUntil.IsZero() {
		return RuntimeBindingStageLaunchOpenReceipt{}, errors.New("runtime binding launch was not opened by verification")
	}
	if err := verifyRuntimeBindingStageLaunchMaterial(opened.material); err != nil {
		return RuntimeBindingStageLaunchOpenReceipt{}, err
	}
	return opened.receipt, nil
}
