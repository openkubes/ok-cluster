package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestStageAuthorizationResolverBindsExactCurrentCursor(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected,
		Receipts: fixture.config.Receipts,
	}
	calls := 0
	resolved, err := ResolveStageAuthorization(context.Background(), resume, StageAuthorizationResolverFunc(
		func(_ context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
			calls++
			if request.Format != StageAuthorizationRequestFormat || request.Audience != authorization.StageAudience ||
				request.PlanDigest != fixture.plan.PlanDigest || request.ContractIdentity != fixture.plan.ContractIdentity ||
				request.ContractRevision != fixture.plan.IntentRevision || request.EnablementRevision != fixture.plan.EnablementRevision ||
				request.PlatformRevision != fixture.plan.PlatformRevision || request.ExecutionFixture != fixture.plan.ExecutionFixture ||
				request.StageID != "target-credential" || request.StageOrder != 8 || request.Operation != "IssueTargetCredential" ||
				request.Authority != "workload" || len(request.Predecessors) != 1 || request.Predecessors[0].StageID != "target-access" ||
				request.MaxUses != 1 || !stageReceiptPrefixDigestPattern.MatchString(request.RequestDigest) {
				t.Fatalf("unexpected authorization request: %#v", request)
			}
			request.Predecessors[0].ReceiptDigest = runnerStageSHA("f")
			return StageAuthorizationSource{
				GrantPath: fixture.config.GrantPath, PublicKeyPath: fixture.config.GrantPublicKeyPath,
				EvaluationTime: fixture.config.EvaluationTime,
			}, nil
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("resolver calls=%d, want 1", calls)
	}
	receipt, err := resolved.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != "ok147-resolved-stage-authorization/v1" || receipt.State != "VERIFIED" ||
		receipt.RequestDigest == "" || receipt.AuthorizationDigest == "" || receipt.PlanDigest != fixture.plan.PlanDigest ||
		receipt.StageID != "target-credential" || receipt.Operation != "IssueTargetCredential" || receipt.Authority != "workload" || receipt.MaxUses != 1 {
		t.Fatalf("unexpected resolved authorization receipt: %#v", receipt)
	}
	source, err := resolved.Source()
	if err != nil || source.GrantPath != fixture.config.GrantPath || source.PublicKeyPath != fixture.config.GrantPublicKeyPath || source.EvaluationTime != fixture.config.EvaluationTime {
		t.Fatalf("unexpected verified source: %#v %v", source, err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{fixture.config.GrantPath, fixture.config.GrantPublicKeyPath, "endpoint", "token"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("public receipt exposed private runtime input %q", forbidden)
		}
	}
}

func TestStageAuthorizationResolverPreservesExplicitEmptyFirstStagePredecessors(t *testing.T) {
	fixture := submissionBundleFixture(t, false, "")
	resume := StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected,
		Receipts: []StageReceiptSource{},
	}
	resolved, err := ResolveStageAuthorization(context.Background(), resume, StageAuthorizationResolverFunc(
		func(_ context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
			if request.StageID != "provider-prerequisites" || request.Predecessors == nil || len(request.Predecessors) != 0 {
				t.Fatalf("first-stage predecessors are not an explicit empty set: %#v", request.Predecessors)
			}
			if _, err := request.Bytes(); err != nil {
				t.Fatalf("first-stage request is not serializable: %v", err)
			}
			return StageAuthorizationSource{
				GrantPath: fixture.config.GrantPath, PublicKeyPath: fixture.config.GrantPublicKeyPath,
				EvaluationTime: fixture.config.EvaluationTime,
			}, nil
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := resolved.Receipt()
	if err != nil || receipt.StageID != "provider-prerequisites" {
		t.Fatalf("unexpected first-stage authorization receipt: %#v %v", receipt, err)
	}
}

func TestStageAuthorizationResolverRejectsWrongGrantAndReadOnlyCursor(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts}
	foreign := targetRegistrationBundleFixture(t)
	if _, err := ResolveStageAuthorization(context.Background(), resume, StageAuthorizationResolverFunc(
		func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error) {
			return StageAuthorizationSource{
				GrantPath: foreign.config.GrantPath, PublicKeyPath: foreign.config.GrantPublicKeyPath,
				EvaluationTime: foreign.config.EvaluationTime,
			}, nil
		},
	)); err == nil {
		t.Fatal("foreign stage grant was accepted")
	}

	aggregate := aggregateEvidenceBundleFixture(t)
	readOnly := StageResumeConfig{
		PlanPath: aggregate.PlanPath, PlanExpected: aggregate.PlanExpected,
		Receipts: append([]StageReceiptSource(nil), aggregate.Receipts[:10]...),
	}
	calls := 0
	if _, err := ResolveStageAuthorization(context.Background(), readOnly, StageAuthorizationResolverFunc(
		func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error) {
			calls++
			return StageAuthorizationSource{}, nil
		},
	)); err == nil || calls != 0 {
		t.Fatalf("read-only cursor reached authority resolver: calls=%d err=%v", calls, err)
	}
}

func TestStageAuthorizationResolverFailsClosedBeforeAndAfterResolution(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts}
	if _, err := ResolveStageAuthorization(context.Background(), resume, nil); err == nil {
		t.Fatal("nil resolver was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if _, err := ResolveStageAuthorization(cancelled, resume, StageAuthorizationResolverFunc(
		func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error) {
			calls++
			return StageAuthorizationSource{}, nil
		},
	)); err == nil || calls != 0 {
		t.Fatalf("cancelled request reached resolver: calls=%d err=%v", calls, err)
	}

	ctx, stop := context.WithCancel(context.Background())
	if _, err := ResolveStageAuthorization(ctx, resume, StageAuthorizationResolverFunc(
		func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error) {
			stop()
			return StageAuthorizationSource{
				GrantPath: fixture.config.GrantPath, PublicKeyPath: fixture.config.GrantPublicKeyPath,
				EvaluationTime: fixture.config.EvaluationTime,
			}, nil
		},
	)); err == nil {
		t.Fatal("authorization returned after context cancellation")
	}
	if _, err := (ResolvedStageAuthorization{}).Source(); err == nil {
		t.Fatal("unverified authorization exposed its source")
	}
}

func TestStageAuthorizationRequestDigestChangesWithPredecessor(t *testing.T) {
	fixture := targetCredentialBundleFixture(t)
	plan, cursor, _, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: fixture.config.PlanPath, PlanExpected: fixture.config.PlanExpected, Receipts: fixture.config.Receipts,
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := cursor.Decision()
	request, err := newStageAuthorizationRequest(plan, decision)
	if err != nil {
		t.Fatal(err)
	}
	original := request.RequestDigest
	request.Predecessors[0].ReceiptDigest = digest.SHA256([]byte("different predecessor"))
	changed, err := stageAuthorizationRequestDigest(request)
	if err != nil || changed == original {
		t.Fatalf("predecessor change did not change request identity: %s %s %v", original, changed, err)
	}
}
