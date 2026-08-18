package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	StageAuthorizationRequestFormat         = "ok147-stage-authorization-request/v1"
	ResolvedStageAuthorizationReceiptFormat = "ok147-resolved-stage-authorization/v1"
)

var stageAuthorizationRequestNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,127}$`)

// StageAuthorizationRequest is the redaction-safe, canonical input supplied
// to an authority after the direct predecessor receipt exists. It contains no
// credential, endpoint, local path or grant material.
type StageAuthorizationRequest struct {
	Format             string                    `json:"format"`
	RequestDigest      string                    `json:"requestDigest"`
	Audience           string                    `json:"audience"`
	PlanDigest         string                    `json:"planDigest"`
	ContractIdentity   contract.Identity         `json:"contractIdentity"`
	ContractRevision   string                    `json:"contractRevision"`
	EnablementRevision string                    `json:"enablementRevision"`
	PlatformRevision   string                    `json:"platformRevision"`
	ExecutionFixture   string                    `json:"executionFixture"`
	StageID            string                    `json:"stageId"`
	StageOrder         int                       `json:"stageOrder"`
	StageDigest        string                    `json:"stageDigest"`
	Operation          string                    `json:"operation"`
	Authority          string                    `json:"authority"`
	Predecessors       []stagecursor.Predecessor `json:"predecessors"`
	MaxUses            int                       `json:"maxUses"`
}

type stageAuthorizationRequestPayload struct {
	Format             string                    `json:"format"`
	Audience           string                    `json:"audience"`
	PlanDigest         string                    `json:"planDigest"`
	ContractIdentity   contract.Identity         `json:"contractIdentity"`
	ContractRevision   string                    `json:"contractRevision"`
	EnablementRevision string                    `json:"enablementRevision"`
	PlatformRevision   string                    `json:"platformRevision"`
	ExecutionFixture   string                    `json:"executionFixture"`
	StageID            string                    `json:"stageId"`
	StageOrder         int                       `json:"stageOrder"`
	StageDigest        string                    `json:"stageDigest"`
	Operation          string                    `json:"operation"`
	Authority          string                    `json:"authority"`
	Predecessors       []stagecursor.Predecessor `json:"predecessors"`
	MaxUses            int                       `json:"maxUses"`
}

// StageAuthorizationSource points at one bounded signed grant and its trust
// key. Paths remain private runtime input and never enter the public receipt.
type StageAuthorizationSource struct {
	GrantPath      string
	PublicKeyPath  string
	EvaluationTime time.Time
}

type StageAuthorizationResolver interface {
	ResolveStageAuthorization(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error)
}

type StageAuthorizationResolverFunc func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error)

func (resolve StageAuthorizationResolverFunc) ResolveStageAuthorization(ctx context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
	return resolve(ctx, request)
}

type ResolvedStageAuthorizationReceipt struct {
	Format              string `json:"format"`
	State               string `json:"state"`
	RequestDigest       string `json:"requestDigest"`
	AuthorizationDigest string `json:"authorizationDigest"`
	GrantID             string `json:"grantId"`
	KeyID               string `json:"keyId"`
	PlanDigest          string `json:"planDigest"`
	StageID             string `json:"stageId"`
	StageDigest         string `json:"stageDigest"`
	Operation           string `json:"operation"`
	Authority           string `json:"authority"`
	PredecessorDigest   string `json:"predecessorDigest"`
	NotAfter            string `json:"notAfter"`
	MaxUses             int    `json:"maxUses"`
}

type ResolvedStageAuthorization struct {
	request  StageAuthorizationRequest
	source   StageAuthorizationSource
	receipt  ResolvedStageAuthorizationReceipt
	verified bool
}

func (request StageAuthorizationRequest) Bytes() ([]byte, error) {
	requestDigest, err := stageAuthorizationRequestDigest(request)
	if err != nil || request.RequestDigest != requestDigest || request.Format != StageAuthorizationRequestFormat ||
		request.Audience != authorization.StageAudience || request.MaxUses != 1 || request.StageOrder < 1 ||
		!stageAuthorizationRequestNamePattern.MatchString(request.StageID) || strings.TrimSpace(request.Operation) != request.Operation || request.Operation == "" ||
		!stageAuthorizationRequestNamePattern.MatchString(request.Authority) || request.Predecessors == nil {
		return nil, errors.New("stage authorization request was not produced by verification")
	}
	for _, value := range []string{
		request.RequestDigest, request.PlanDigest, request.ContractRevision, request.EnablementRevision,
		request.PlatformRevision, request.ExecutionFixture, request.StageDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return nil, errors.New("stage authorization request digest identity is invalid")
		}
	}
	if request.ContractIdentity.Name == "" || request.ContractIdentity.Namespace == "" {
		return nil, errors.New("stage authorization request Contract identity is incomplete")
	}
	for _, predecessor := range request.Predecessors {
		if !stageAuthorizationRequestNamePattern.MatchString(predecessor.StageID) || !stageReceiptPrefixDigestPattern.MatchString(predecessor.ReceiptDigest) {
			return nil, errors.New("stage authorization request predecessor is invalid")
		}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return contract.JCS(value)
}

// ResolveStageAuthorization derives the only acceptable authorization
// request from the current cursor, invokes the external authority once and
// re-verifies the returned grant before exposing its private file source to a
// stage bundle. It performs no ledger or Kubernetes request.
func ResolveStageAuthorization(ctx context.Context, resume StageResumeConfig, resolver StageAuthorizationResolver) (ResolvedStageAuthorization, error) {
	if resolver == nil {
		return ResolvedStageAuthorization{}, errors.New("stage authorization resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedStageAuthorization{}, errors.New("stage authorization context is unavailable")
	}
	plan, cursor, _, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		return ResolvedStageAuthorization{}, errors.New("verify stage authorization cursor")
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || !decision.RequiresAuthorization || decision.Operation == "" {
		return ResolvedStageAuthorization{}, errors.New("verified cursor does not select a mutating stage")
	}
	request, err := newStageAuthorizationRequest(plan, decision)
	if err != nil {
		return ResolvedStageAuthorization{}, err
	}
	source, err := resolver.ResolveStageAuthorization(ctx, cloneStageAuthorizationRequest(request))
	if err != nil {
		return ResolvedStageAuthorization{}, errors.New("resolve stage authorization")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedStageAuthorization{}, errors.New("stage authorization context became unavailable")
	}
	if source.GrantPath == "" || source.PublicKeyPath == "" || source.EvaluationTime.IsZero() {
		return ResolvedStageAuthorization{}, errors.New("resolved stage authorization source is incomplete")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return ResolvedStageAuthorization{}, errors.New("load stage authorization predecessors")
	}
	grant, err := authorization.LoadStage(source.GrantPath, source.PublicKeyPath, plan, decision.StageID, predecessors, source.EvaluationTime)
	if err != nil {
		return ResolvedStageAuthorization{}, errors.New("verify resolved stage authorization")
	}
	if _, err := authorization.BindStageGrant(grant, plan, decision.StageID, predecessors); err != nil {
		return ResolvedStageAuthorization{}, errors.New("bind resolved stage authorization")
	}
	grantReceipt := grant.Receipt()
	receipt := ResolvedStageAuthorizationReceipt{
		Format: ResolvedStageAuthorizationReceiptFormat, State: "VERIFIED",
		RequestDigest: request.RequestDigest, AuthorizationDigest: grantReceipt.AuthorizationDigest,
		GrantID: grantReceipt.GrantID, KeyID: grantReceipt.KeyID, PlanDigest: grantReceipt.PlanDigest,
		StageID: grantReceipt.StageID, StageDigest: grantReceipt.StageDigest,
		Operation: grantReceipt.Operation, Authority: grantReceipt.Authority,
		PredecessorDigest: grantReceipt.PredecessorDigest, NotAfter: grantReceipt.NotAfter,
		MaxUses: grantReceipt.MaxUses,
	}
	return ResolvedStageAuthorization{request: request, source: source, receipt: receipt, verified: true}, nil
}

func (resolved ResolvedStageAuthorization) Receipt() (ResolvedStageAuthorizationReceipt, error) {
	if err := verifyResolvedStageAuthorization(resolved); err != nil {
		return ResolvedStageAuthorizationReceipt{}, err
	}
	return resolved.receipt, nil
}

func (resolved ResolvedStageAuthorization) Source() (StageAuthorizationSource, error) {
	if err := verifyResolvedStageAuthorization(resolved); err != nil {
		return StageAuthorizationSource{}, err
	}
	return resolved.source, nil
}

func newStageAuthorizationRequest(plan stageplan.Binding, decision stagecursor.Decision) (StageAuthorizationRequest, error) {
	stage, stageDigest, err := plan.Stage(decision.StageID)
	if err != nil || !stageplan.IsMutating(stage) || decision.Format != stagecursor.DecisionFormat ||
		decision.State != "NEXT" || !decision.RequiresAuthorization || decision.PlanDigest != plan.PlanDigest ||
		decision.StageOrder != stage.Order || decision.StageDigest != stageDigest || decision.Operation != stage.GrantOperation ||
		decision.Authority != stage.Authority || len(decision.Predecessors) != len(stage.Requires) {
		return StageAuthorizationRequest{}, errors.New("stage authorization request cursor is invalid")
	}
	for index, predecessor := range decision.Predecessors {
		if predecessor.StageID != stage.Requires[index] || !stageReceiptPrefixDigestPattern.MatchString(predecessor.ReceiptDigest) {
			return StageAuthorizationRequest{}, errors.New("stage authorization request predecessor is invalid")
		}
	}
	request := StageAuthorizationRequest{
		Format: StageAuthorizationRequestFormat, Audience: authorization.StageAudience,
		PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity,
		ContractRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest,
		Operation: stage.GrantOperation, Authority: stage.Authority,
		Predecessors: append([]stagecursor.Predecessor{}, decision.Predecessors...), MaxUses: 1,
	}
	request.RequestDigest, err = stageAuthorizationRequestDigest(request)
	if err != nil {
		return StageAuthorizationRequest{}, errors.New("canonicalize stage authorization request")
	}
	return request, nil
}

func cloneStageAuthorizationRequest(request StageAuthorizationRequest) StageAuthorizationRequest {
	request.Predecessors = append([]stagecursor.Predecessor{}, request.Predecessors...)
	return request
}

func verifyResolvedStageAuthorization(resolved ResolvedStageAuthorization) error {
	if !resolved.verified || resolved.receipt.Format != ResolvedStageAuthorizationReceiptFormat || resolved.receipt.State != "VERIFIED" ||
		resolved.receipt.RequestDigest != resolved.request.RequestDigest || resolved.receipt.PlanDigest != resolved.request.PlanDigest ||
		resolved.receipt.StageID != resolved.request.StageID || resolved.receipt.StageDigest != resolved.request.StageDigest ||
		resolved.receipt.Operation != resolved.request.Operation || resolved.receipt.Authority != resolved.request.Authority ||
		resolved.receipt.MaxUses != 1 || resolved.source.GrantPath == "" || resolved.source.PublicKeyPath == "" || resolved.source.EvaluationTime.IsZero() {
		return errors.New("stage authorization resolution was not produced by verification")
	}
	for _, value := range []string{
		resolved.receipt.RequestDigest, resolved.receipt.AuthorizationDigest, resolved.receipt.PlanDigest,
		resolved.receipt.StageDigest, resolved.receipt.PredecessorDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("resolved stage authorization digest identity is invalid")
		}
	}
	requestDigest, err := stageAuthorizationRequestDigest(resolved.request)
	if err != nil || requestDigest != resolved.request.RequestDigest {
		return errors.New("stage authorization request identity changed after verification")
	}
	return nil
}

func stageAuthorizationRequestDigest(request StageAuthorizationRequest) (string, error) {
	payload := stageAuthorizationRequestPayload{
		Format: request.Format, Audience: request.Audience, PlanDigest: request.PlanDigest,
		ContractIdentity: request.ContractIdentity, ContractRevision: request.ContractRevision,
		EnablementRevision: request.EnablementRevision, PlatformRevision: request.PlatformRevision,
		ExecutionFixture: request.ExecutionFixture, StageID: request.StageID, StageOrder: request.StageOrder,
		StageDigest: request.StageDigest, Operation: request.Operation, Authority: request.Authority,
		Predecessors: append([]stagecursor.Predecessor{}, request.Predecessors...), MaxUses: request.MaxUses,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}
