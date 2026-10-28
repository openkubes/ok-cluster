package bootstrapauthority

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
	"github.com/openkubes/ok-cluster/internal/issuersourcecheck"
)

// ObserverTaskSource stays inside the privileged platform task. It is not a
// public request/result, runner input or permission to read any Secret. Real
// source access, atomic snapshot identity and adapter privileges need review.
type ObserverTaskSource struct {
	Metadata, CertificateDER, PrivateKeyPEM []byte
}

// ObserverTaskIssueInput is passed only to a fixed trusted in-process adapter,
// never to a caller-selected plugin, Job, command or browser. That adapter must
// enforce the approved signing policy before using its key; validating a result
// afterward cannot undo a bad signature or contain a compromised signer.
type ObserverTaskIssueInput struct {
	Request               bootstrapcheck.Request
	Inputs                bootstrapcheck.ObserverInputs
	Claim                 Claim
	Source                ObserverTaskSource
	IssuedAt              time.Time
	PollTimeout, Overhead time.Duration
}

// ObserverTaskConfig is trusted platform-owner configuration, not a wire schema.
// Inputs must already come from authenticated operation/plan/predecessor evidence.
// Matching a signed candidate request does not establish that evidence or grant
// source access. This candidate supplies no real reader, signer, installation,
// endpoint or CLI/runner adapter, and approves none of those capabilities.
type ObserverTaskConfig struct {
	Authority   *Authority
	Inputs      bootstrapcheck.ObserverInputs
	SourceOwner bootstrapcheck.SourceOwner
	ReadSource  func(context.Context, bootstrapcheck.Binding) (ObserverTaskSource, error)
	IssueResult func(context.Context, ObserverTaskIssueInput) (SignedResult, error)
	Clock       func() time.Time
}

// ObserverTask is an experimental one-call task core, not an activated platform
// issuer. All outcomes consume this instance. There is no retry, reset, fallback,
// historical-result delivery or runner execution. Cross-process operation STOP,
// real store fencing and no Job recreation must be enforced by the future owner.
// In particular an unknown, uncommitted claim write cannot be durably remembered
// by this process-local used bit or by an apparently empty coordination store.
type ObserverTask struct {
	mu     sync.Mutex
	config ObserverTaskConfig
	used   bool
	ready  bool
}

func NewObserverTask(config ObserverTaskConfig) (*ObserverTask, error) {
	if config.Authority == nil || config.ReadSource == nil || config.IssueResult == nil || config.Clock == nil ||
		len(config.Inputs.CADER) == 0 || len(config.Inputs.CADER) > 65536 ||
		config.SourceOwner.Name == "" || strings.TrimSpace(config.SourceOwner.Name) != config.SourceOwner.Name ||
		(config.SourceOwner.APIVersion != "cluster.x-k8s.io/v1beta1" && config.SourceOwner.APIVersion != "cluster.x-k8s.io/v1beta2") {
		return nil, stoppedObserverTask("configuration")
	}
	config.Inputs.CADER = append([]byte(nil), config.Inputs.CADER...)
	ca, err := x509.ParseCertificate(config.Inputs.CADER)
	if err != nil {
		return nil, stoppedObserverTask("configuration")
	}
	if public, ok := ca.PublicKey.(ed25519.PublicKey); ok &&
		(digest(public) == config.Authority.trust.StageKeyID || digest(public) == config.Authority.trust.EvidenceKeyID) {
		return nil, stoppedObserverTask("CA key separation")
	}
	return &ObserverTask{config: config, ready: true}, nil
}

func stoppedObserverTask(phase string) error {
	// Phase labels are fixed code, never adapter diagnostics or input material.
	return fmt.Errorf("observer task %s: %w", phase, ErrStop)
}

func copyObserverTaskSource(source ObserverTaskSource) ObserverTaskSource {
	return ObserverTaskSource{
		Metadata: append([]byte(nil), source.Metadata...), CertificateDER: append([]byte(nil), source.CertificateDER...),
		PrivateKeyPEM: append([]byte(nil), source.PrivateKeyPEM...),
	}
}

func copyObserverTaskResult(result SignedResult) SignedResult {
	result.Result.CertificateDER = append([]byte(nil), result.Result.CertificateDER...)
	result.Signature = append([]byte(nil), result.Signature...)
	return result
}

// Run returns only the public authenticated result, after Complete confirms its
// persistence. It is not a stage grant, operation success or convergence proof.
// The request must stay active for the entire task, not only at initial verify.
func (task *ObserverTask) Run(ctx context.Context, request SignedRequest) (SignedResult, error) {
	if task == nil || !task.ready {
		return SignedResult{}, stoppedObserverTask("configuration")
	}
	task.mu.Lock()
	if task.used {
		task.mu.Unlock()
		return SignedResult{}, ErrConsumed
	}
	task.used = true
	task.mu.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return SignedResult{}, stoppedObserverTask("context")
	}
	if len(request.Request.CSRDER) == 0 || len(request.Request.CSRDER) > 16384 || len(request.Signature) != ed25519.SignatureSize {
		return SignedResult{}, stoppedObserverTask("request")
	}
	request.Request.CSRDER = append([]byte(nil), request.Request.CSRDER...)
	request.Signature = append([]byte(nil), request.Signature...)
	c := task.config
	var lastTime time.Time
	verifyNow := func() (VerifiedRequest, time.Time, error) {
		if ctx.Err() != nil {
			return VerifiedRequest{}, time.Time{}, stoppedObserverTask("context")
		}
		// UTC strips monotonic-clock data so regression checks and signed wall
		// timestamps use the same clock domain, including across adapters.
		now := c.Clock().UTC()
		if !lastTime.IsZero() && now.Before(lastTime) {
			return VerifiedRequest{}, time.Time{}, stoppedObserverTask("clock")
		}
		verified, err := c.Authority.Verify(request, c.Inputs, now)
		if err != nil {
			return VerifiedRequest{}, time.Time{}, stoppedObserverTask("request")
		}
		lastTime = now
		return verified, now, nil
	}
	readSource := func() (ObserverTaskSource, error) {
		if ctx.Err() != nil {
			return ObserverTaskSource{}, stoppedObserverTask("context")
		}
		source, err := c.ReadSource(ctx, c.Inputs.Expected)
		if err != nil {
			return ObserverTaskSource{}, stoppedObserverTask("source read")
		}
		// Mirror the existing validators' byte bounds before allocating copies.
		if len(source.Metadata) > 256*1024 || len(source.CertificateDER) > 65536 || len(source.PrivateKeyPEM) > 16384 {
			return ObserverTaskSource{}, stoppedObserverTask("source validation")
		}
		source = copyObserverTaskSource(source)
		if issuersourcecheck.Validate(source.Metadata, source.CertificateDER, source.PrivateKeyPEM, c.Inputs.Expected, c.SourceOwner) != nil {
			return ObserverTaskSource{}, stoppedObserverTask("source validation")
		}
		return source, nil
	}
	initial, startedAt, err := verifyNow()
	if err != nil {
		return SignedResult{}, err
	}
	// Adapters receive a cooperative deadline no later than the signed request
	// window or parent deadline. This cannot preempt an adapter that ignores ctx;
	// the future fixed task also needs enforced process/Job lifetime and no replay.
	ctx, cancel := context.WithTimeout(ctx, request.NotAfter.Sub(startedAt))
	defer cancel()
	state, err := c.Authority.inspectVerified(ctx, initial)
	if err != nil {
		return SignedResult{}, stoppedObserverTask("coordination inspection")
	}
	if state.State != "EMPTY_NOT_AUTHORIZED" {
		return SignedResult{}, fmt.Errorf("observer task existing slot: %w", ErrConsumed)
	}
	if _, err := readSource(); err != nil {
		return SignedResult{}, err
	}
	verified, claimedAt, err := verifyNow()
	if err != nil {
		return SignedResult{}, err
	}
	claim, err := c.Authority.Claim(ctx, verified, claimedAt)
	if err != nil {
		if errors.Is(err, ErrConsumed) {
			return SignedResult{}, fmt.Errorf("observer task claim: %w", ErrConsumed)
		}
		return SignedResult{}, stoppedObserverTask("claim")
	}
	if _, _, err := verifyNow(); err != nil {
		return SignedResult{}, err
	}
	// Obtain another snapshot, not a fallback to the pre-claim bytes. Actual
	// freshness/atomicity is an obligation of the reviewed source adapter.
	source, err := readSource()
	if err != nil {
		return SignedResult{}, err
	}
	_, issuedAt, err := verifyNow()
	if err != nil {
		return SignedResult{}, err
	}
	ca, err := x509.ParseCertificate(source.CertificateDER)
	if err != nil || issuedAt.Before(ca.NotBefore) || !issuedAt.Before(ca.NotAfter) {
		return SignedResult{}, stoppedObserverTask("CA signing window")
	}
	remaining := ca.NotAfter.Sub(issuedAt)
	if remaining <= request.PollTimeout || request.WrapperOverhead >= remaining-request.PollTimeout {
		return SignedResult{}, stoppedObserverTask("CA observation budget")
	}
	inputs := c.Inputs
	inputs.CADER = append([]byte(nil), inputs.CADER...)
	issueRequest := request.Request
	issueRequest.CSRDER = append([]byte(nil), issueRequest.CSRDER...)
	result, err := c.IssueResult(ctx, ObserverTaskIssueInput{
		Request: issueRequest, Inputs: inputs, Claim: claim, Source: source, IssuedAt: issuedAt,
		PollTimeout: request.PollTimeout, Overhead: request.WrapperOverhead,
	})
	if err != nil {
		return SignedResult{}, stoppedObserverTask("issuance adapter")
	}
	if len(result.Result.CertificateDER) == 0 || len(result.Result.CertificateDER) > 65536 || len(result.Signature) != ed25519.SignatureSize {
		return SignedResult{}, stoppedObserverTask("issuance result")
	}
	result = copyObserverTaskResult(result)
	if !result.IssuedAt.Equal(issuedAt) {
		return SignedResult{}, stoppedObserverTask("issuance timestamp")
	}
	_, completedAt, err := verifyNow()
	if err != nil {
		return SignedResult{}, err
	}
	if c.Authority.Complete(ctx, claim, result, completedAt) != nil {
		return SignedResult{}, stoppedObserverTask("result persistence")
	}
	return result, nil
}
