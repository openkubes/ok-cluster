package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestPostRuntimeExecutionComposesExactSuffixWithDynamicAuthorization(t *testing.T) {
	config, factories, calls, requests := postRuntimeExecutionFixture(t)
	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != PostRuntimeExecutionReceiptFormat || receipt.State != "SUCCEEDED" || receipt.StoppedAt != "" ||
		len(receipt.Checkpoints) != 5 || len(receipt.ResolvedAuthorizations) != 2 {
		t.Fatalf("unexpected post-runtime execution receipt: %#v", receipt)
	}
	if !reflect.DeepEqual(*calls, postRuntimeStageOrder) {
		t.Fatalf("post-runtime execution order differs: %v", *calls)
	}
	if len(*requests) != 2 || (*requests)[0].StageID != "target-registration" || (*requests)[1].StageID != "platform-applications" ||
		(*requests)[0].Predecessors[0].StageID != "target-credential" || (*requests)[1].Predecessors[0].StageID != "target-registration" ||
		(*requests)[0].RequestDigest == (*requests)[1].RequestDigest {
		t.Fatalf("unexpected dynamic authorization sequence: %#v", *requests)
	}
	for index, stageID := range postRuntimeStageOrder[:4] {
		path := filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles[stageID])
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("receipt %d was not persisted privately: %#v %v", index, info, statErr)
		}
	}
	if second, err := executor.Run(context.Background()); err == nil || second.State != "STOPPED" || second.StoppedAt != "target-credential" || len(*calls) != 5 {
		t.Fatalf("single-use executor ran twice: %#v calls=%v err=%v", second, *calls, err)
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{config.ReceiptDirectory, "token", "endpoint", "kubeconfig"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("public execution receipt exposed %q", forbidden)
		}
	}
}

func TestPostRuntimeExecutionRejectsUnsafeReceiptDestinationBeforeExecution(t *testing.T) {
	config, factories, calls, _ := postRuntimeExecutionFixture(t)
	if err := os.Chmod(config.ReceiptDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openPostRuntimeExecution(config, factories); err == nil || len(*calls) != 0 {
		t.Fatalf("broad receipt directory was accepted: calls=%v err=%v", *calls, err)
	}
}

func TestPostRuntimeExecutionStopsAfterDurableReceiptWhenNextGrantIsUnavailable(t *testing.T) {
	config, factories, calls, _ := postRuntimeExecutionFixture(t)
	resolverCalls := 0
	config.Authorization = StageAuthorizationResolverFunc(func(context.Context, StageAuthorizationRequest) (StageAuthorizationSource, error) {
		resolverCalls++
		return StageAuthorizationSource{}, errors.New("authority unavailable with private details")
	})
	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "target-registration" || len(receipt.Checkpoints) != 1 || len(receipt.ResolvedAuthorizations) != 0 {
		t.Fatalf("unavailable authority did not stop after Stage 8: %#v %v", receipt, err)
	}
	if resolverCalls != 1 || !reflect.DeepEqual(*calls, []string{"target-credential"}) {
		t.Fatalf("later stage ran after authority failure: resolver=%d calls=%v", resolverCalls, *calls)
	}
	if _, err := os.Lstat(filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles["target-credential"])); err != nil {
		t.Fatal("durable Stage-8 receipt was not retained")
	}
	for _, stageID := range postRuntimeStageOrder[1:4] {
		if _, err := os.Lstat(filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles[stageID])); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later receipt %s exists after authorization stop: %v", stageID, err)
		}
	}
}

func TestPostRuntimeExecutionContinuesFromReceiptBoundCredentialRecovery(t *testing.T) {
	config, factories, calls, _ := postRuntimeExecutionFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(config.TargetCredential)
	if err != nil {
		t.Fatal(err)
	}
	now := config.TargetCredential.EvaluationTime.Add(time.Minute)
	credentialAPI, requests := newTargetCredentialExecutionAPI(t, now, 201)
	defer credentialAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	runtime := targetCredentialExecutionRuntime(t, targetCredentialBundleTestFixture{
		config: config.TargetCredential, plan: bundle.plan, policyDigest: bundle.receipt.PolicyDigest,
		accessDigest: bundle.receipt.TargetAccessArtifactDigest,
	}, ledgerAPI.Server, credentialAPI, now)
	original, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	run, handoff, err := original.RunHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handoff.StageReceiptBytes()
	if err != nil {
		t.Fatal(err)
	}
	priorPath := filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles["target-credential"])
	if err := os.WriteFile(priorPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	prior := StageReceiptSource{Path: priorPath, Digest: run.StageReceiptDigest}
	recoveryGrantRoot := t.TempDir()
	config.TargetCredentialRun = runtime
	config.TargetCredentialRecovery = &PostRuntimeTargetCredentialRecoveryConfig{
		StageReceipt: prior,
		Authorization: TargetCredentialRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetCredentialRecoveryGrant(t, recoveryGrantRoot, request, now), nil
		}),
	}
	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "SUCCEEDED" || receipt.ResolvedRecoveryAuthorization == nil || receipt.TargetCredentialRecovery == nil ||
		receipt.TargetCredentialRecovery.State != "REISSUED" || receipt.Checkpoints[0].StageReceiptDigest != prior.Digest ||
		len(receipt.ResolvedAuthorizations) != 2 || requests.Load() != 2 {
		t.Fatalf("post-runtime recovery did not continue exact suffix: %#v requests=%d", receipt, requests.Load())
	}
	if !reflect.DeepEqual(*calls, postRuntimeStageOrder[1:]) {
		t.Fatalf("normal Stage-8 factory ran during recovery: calls=%v", *calls)
	}
	stored, err := os.ReadFile(priorPath)
	if err != nil || digest.SHA256(stored) != prior.Digest {
		t.Fatalf("recovery changed prior Stage-8 receipt: %v", err)
	}
}

func TestPostRuntimeExecutionContinuesFromReceiptBoundRegistrationRecovery(t *testing.T) {
	config, factories, calls, requests := postRuntimeExecutionFixture(t)
	bundle, err := LoadTargetCredentialStageBundle(config.TargetCredential)
	if err != nil {
		t.Fatal(err)
	}
	now := config.TargetCredential.EvaluationTime.Add(time.Minute)
	credentialAPI, tokenRequests := newTargetCredentialExecutionAPI(t, now, 201)
	defer credentialAPI.Close()
	ledgerAPI := newRuntimeBindingLedgerAPI(t)
	defer ledgerAPI.Close()
	runtime := targetCredentialExecutionRuntime(t, targetCredentialBundleTestFixture{
		config: config.TargetCredential, plan: bundle.plan, policyDigest: bundle.receipt.PolicyDigest,
		accessDigest: bundle.receipt.TargetAccessArtifactDigest,
	}, ledgerAPI.Server, credentialAPI, now)
	original, err := bundle.Open(runtime)
	if err != nil {
		t.Fatal(err)
	}
	stageEightRun, stageEightHandoff, err := original.RunHandoff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stageEightRaw, err := stageEightHandoff.StageReceiptBytes()
	if err != nil {
		t.Fatal(err)
	}
	stageEightPath := filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles["target-credential"])
	if err := os.WriteFile(stageEightPath, stageEightRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	stageEight := StageReceiptSource{Path: stageEightPath, Digest: stageEightRun.StageReceiptDigest}

	resume := StageResumeConfig{PlanPath: config.TargetCredential.PlanPath, PlanExpected: config.TargetCredential.PlanExpected,
		Receipts: append(append([]StageReceiptSource(nil), config.TargetCredential.Receipts...), stageEight)}
	plan, cursor, _, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		t.Fatal(err)
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		t.Fatal(err)
	}
	stageNine, err := stagereceipt.New(plan, "target-registration", predecessors, "SUCCEEDED", "ATTEMPTED",
		digest.SHA256([]byte("original-registration-outcome")), digest.SHA256([]byte("original-registration-evidence")), now)
	if err != nil {
		t.Fatal(err)
	}
	stageNineRaw, err := stageNine.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	stageNineDigest, err := stageNine.Digest()
	if err != nil {
		t.Fatal(err)
	}
	stageNinePath := filepath.Join(config.ReceiptDirectory, postRuntimeReceiptFiles["target-registration"])
	if err := os.WriteFile(stageNinePath, stageNineRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	stageNineSource := StageReceiptSource{Path: stageNinePath, Digest: stageNineDigest}

	grantRoot := t.TempDir()
	config.TargetCredentialRun = runtime
	config.TargetCredentialRecovery = &PostRuntimeTargetCredentialRecoveryConfig{
		StageReceipt: stageEight,
		Authorization: TargetCredentialRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetCredentialRecoveryGrant(t, grantRoot, request, now), nil
		}),
	}
	config.TargetRegistrationRecovery = &PostRuntimeTargetRegistrationRecoveryConfig{
		StageReceipt: stageNineSource,
		Authorization: TargetRegistrationRecoveryAuthorizationResolverFunc(func(_ context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
			return writeTargetRegistrationRecoveryGrant(t, grantRoot, request, now), nil
		}),
	}
	factories.registrationRecovery = func(_ context.Context, recovery TargetRegistrationRecoveryConfig) (TargetRegistrationRecoveryReceipt, error) {
		*calls = append(*calls, "target-registration")
		if recovery.PriorStageReceipt.Digest != stageNineDigest || recovery.Handoff == nil || !recovery.Authorization.verified {
			t.Fatalf("registration recovery config differs: %#v", recovery)
		}
		return TargetRegistrationRecoveryReceipt{
			Format: TargetRegistrationRecoveryReceiptFormat, State: "REFRESHED", PlanDigest: plan.PlanDigest,
			PriorStageReceiptDigest: stageNineDigest, RecoveryRequestDigest: recovery.Authorization.request.RequestDigest,
		}, nil
	}

	executor, err := openPostRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "SUCCEEDED" || receipt.ResolvedRecoveryAuthorization == nil || receipt.TargetCredentialRecovery == nil ||
		receipt.ResolvedRegistrationRecoveryAuthorization == nil || receipt.TargetRegistrationRecovery == nil ||
		receipt.TargetRegistrationRecovery.State != "REFRESHED" || len(receipt.ResolvedAuthorizations) != 1 || len(receipt.Checkpoints) != 5 ||
		receipt.Checkpoints[0].StageReceiptDigest != stageEight.Digest || receipt.Checkpoints[1].StageReceiptDigest != stageNineDigest ||
		tokenRequests.Load() != 2 {
		t.Fatalf("post-runtime registration recovery did not continue exact suffix: %#v tokenRequests=%d", receipt, tokenRequests.Load())
	}
	if !reflect.DeepEqual(*calls, postRuntimeStageOrder[1:]) || len(*requests) != 1 || (*requests)[0].StageID != "platform-applications" {
		t.Fatalf("normal registration path ran during recovery: calls=%v requests=%#v", *calls, *requests)
	}
	storedEight, errEight := os.ReadFile(stageEightPath)
	storedNine, errNine := os.ReadFile(stageNinePath)
	if errEight != nil || errNine != nil || digest.SHA256(storedEight) != stageEight.Digest || digest.SHA256(storedNine) != stageNineDigest {
		t.Fatalf("registration recovery changed historical receipts: stage8=%v stage9=%v", errEight, errNine)
	}
}

func postRuntimeExecutionFixture(t *testing.T) (PostRuntimeExecutionConfig, postRuntimeExecutionFactories, *[]string, *[]StageAuthorizationRequest) {
	t.Helper()
	credential := targetCredentialBundleFixture(t)
	resume := StageResumeConfig{
		PlanPath: credential.config.PlanPath, PlanExpected: credential.config.PlanExpected,
		Receipts: credential.config.Receipts,
	}
	plan, _, prefix, err := loadStageResumeWithPrefix(resume)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledger.Open(filepath.Join(t.TempDir(), "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeMaterialPath, runtimeReceiptPath := writePostRuntimeBindingFiles(t, plan, prefix)
	receiptDirectory := t.TempDir()
	if err := os.Chmod(receiptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	grantDirectory := t.TempDir()
	if err := os.Chmod(grantDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := []string{}
	requests := []StageAuthorizationRequest{}
	sequence := 0
	stageRun := func(stageResume StageResumeConfig, stageID string) (stagereceipt.Verified, string) {
		plan, cursor, _, loadErr := loadStageResumeWithPrefix(stageResume)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		predecessors, predecessorErr := cursor.Predecessors()
		if predecessorErr != nil {
			t.Fatal(predecessorErr)
		}
		sequence++
		mutation := "NOT_APPLICABLE"
		outcome := ""
		if stageID == "target-credential" || stageID == "target-registration" || stageID == "platform-applications" {
			mutation, outcome = "ATTEMPTED", digest.SHA256([]byte("operation-"+stageID))
		}
		verified, receiptErr := stagereceipt.New(plan, stageID, predecessors, "SUCCEEDED", mutation, outcome, digest.SHA256([]byte("evidence-"+stageID)), time.Date(2026, 8, 18, 8, sequence, 0, 0, time.UTC))
		if receiptErr != nil {
			t.Fatal(receiptErr)
		}
		receiptDigest, storeErr := store.StoreStageReceipt(context.Background(), plan, verified, predecessors)
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		return verified, receiptDigest
	}
	resolver := StageAuthorizationResolverFunc(func(_ context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
		requests = append(requests, cloneStageAuthorizationRequest(request))
		return writeResolvedStageGrant(t, grantDirectory, request)
	})
	factories := postRuntimeExecutionFactories{
		credential: func(config TargetCredentialStageBundleConfig, _ TargetCredentialStageRuntimeConfig) (postRuntimeCredentialInvocation, error) {
			return postRuntimeCredentialInvocation{
				ledger: store,
				run: func(context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
					calls = append(calls, "target-credential")
					_, receiptDigest := stageRun(StageResumeConfig{PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts}, "target-credential")
					return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "target-credential", StageReceiptDigest: receiptDigest}, &VerifiedTargetCredentialStageHandoff{verified: true}, nil
				},
			}, nil
		},
		registration: func(stageResume StageResumeConfig, _ *VerifiedTargetCredentialStageHandoff, _ StageAuthorizationSource, _ PostRuntimeTargetRegistrationConfig, _ VerifiedRuntimeBindingMaterial) (postRuntimeStagedInvocation, error) {
			return postRuntimeStagedInvocation{ledger: store, run: func(context.Context) (execution.StagedOperationReceipt, error) {
				calls = append(calls, "target-registration")
				_, receiptDigest := stageRun(stageResume, "target-registration")
				return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "target-registration", StageReceiptDigest: receiptDigest}, nil
			}}, nil
		},
		applications: func(stageResume StageResumeConfig, _ StageAuthorizationSource, _ PostRuntimePlatformApplicationsConfig) (postRuntimeStagedInvocation, error) {
			return postRuntimeStagedInvocation{ledger: store, run: func(context.Context) (execution.StagedOperationReceipt, error) {
				calls = append(calls, "platform-applications")
				_, receiptDigest := stageRun(stageResume, "platform-applications")
				return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "platform-applications", StageReceiptDigest: receiptDigest}, nil
			}}, nil
		},
		observation: func(stageResume StageResumeConfig, _ PostRuntimePlatformObservationConfig) (postRuntimeObservationInvocation, error) {
			return postRuntimeObservationInvocation{ledger: store, run: func(context.Context) (execution.ObservationStageRunReceipt, error) {
				calls = append(calls, "platform-observation")
				_, receiptDigest := stageRun(stageResume, "platform-observation")
				return execution.ObservationStageRunReceipt{Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "platform-observation", StageReceiptDigest: receiptDigest}, nil
			}}, nil
		},
		aggregate: func(stageResume StageResumeConfig, _ PostRuntimeAggregateEvidenceConfig, _ VerifiedRuntimeBindingMaterial) (postRuntimeEvaluationInvocation, error) {
			return postRuntimeEvaluationInvocation{run: func(context.Context) (execution.EvaluationStageRunReceipt, error) {
				calls = append(calls, "aggregate-evidence")
				_, receiptDigest := stageRun(stageResume, "aggregate-evidence")
				return execution.EvaluationStageRunReceipt{Format: execution.EvaluationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: plan.PlanDigest, StageID: "aggregate-evidence", StageReceiptDigest: receiptDigest}, nil
			}}, nil
		},
	}
	config := PostRuntimeExecutionConfig{
		TargetCredential: credential.config, Authorization: resolver,
		RuntimeBinding:   RuntimeBindingMaterialFileConfig{MaterialPath: runtimeMaterialPath, ReceiptPath: runtimeReceiptPath},
		ReceiptDirectory: receiptDirectory,
	}
	return config, factories, &calls, &requests
}

func writePostRuntimeBindingFiles(t *testing.T, binding stageplan.Binding, prefix []stagereceipt.Verified) (string, string) {
	t.Helper()
	lifecycle, _ := prefix[1].Receipt()
	network, _ := prefix[4].Receipt()
	material := RuntimeBindingMaterial{
		Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND", PlanDigest: binding.PlanDigest,
		IntentRevision: binding.IntentRevision, EnablementRevision: binding.EnablementRevision,
		PlatformRevision: binding.PlatformRevision, ExecutionFixture: binding.ExecutionFixture,
		Target: RuntimeBindingTarget{
			Name: binding.ContractIdentity.Name, CAPIClusterUID: targetAccessRuntimeUID,
			TargetIdentityScheme: "capi-cluster-uid/v1", WorkloadAPIEndpoint: "https://192.0.2.20:6443",
			WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: digest.SHA256([]byte("ca")), KubeSystemUID: "kube-system-runtime-uid",
		},
		Storage:  RuntimeBindingStorage{Name: "local-path", UID: "local-path-runtime-uid", Provisioner: "rancher.io/local-path"},
		Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: lifecycle.EvidenceDigest, NetworkEvidenceDigest: network.EvidenceDigest},
	}
	raw, err := canonicalRuntimeBinding(material)
	if err != nil {
		t.Fatal(err)
	}
	receipt := RuntimeBindingMaterialReceipt{
		Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding", PlanDigest: binding.PlanDigest,
		IntentRevision: binding.IntentRevision, TargetClusterUIDDigest: digest.SHA256([]byte(material.Target.CAPIClusterUID)),
		WorkloadAPICADigest: material.Target.WorkloadAPICADigest, KubeSystemUIDDigest: digest.SHA256([]byte(material.Target.KubeSystemUID)),
		LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)), LifecycleEvidenceDigest: lifecycle.EvidenceDigest,
		NetworkEvidenceDigest: network.EvidenceDigest, PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
	}
	root := t.TempDir()
	return writeBundleFile(t, root, "runtime-binding.json", raw), writeBundleFile(t, root, "runtime-binding-receipt.json", mustJSON(t, receipt))
}

func writeResolvedStageGrant(t *testing.T, root string, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
	t.Helper()
	payload := authorization.StagePayload{
		Audience: request.Audience, GrantID: "ok147-runtime-" + request.StageID, Decision: "ALLOW",
		PlanDigest: request.PlanDigest, ContractIdentity: request.ContractIdentity, ContractRevision: request.ContractRevision,
		EnablementRevision: request.EnablementRevision, PlatformRevision: request.PlatformRevision, ExecutionFixture: request.ExecutionFixture,
		StageID: request.StageID, StageOrder: request.StageOrder, StageDigest: request.StageDigest,
		Operation: request.Operation, Authority: request.Authority, MaxUses: request.MaxUses,
		NotBefore: "2026-08-18T07:59:00Z", NotAfter: "2026-08-18T08:20:00Z",
	}
	for _, predecessor := range request.Predecessors {
		payload.Predecessors = append(payload.Predecessors, authorization.StagePredecessor{StageID: predecessor.StageID, OutcomeDigest: predecessor.ReceiptDigest})
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return StageAuthorizationSource{}, err
	}
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		return StageAuthorizationSource{}, err
	}
	envelope := mustJSON(t, map[string]any{
		"format": authorization.StageFormat, "payload": payload,
		"signature": map[string]any{"algorithm": "Ed25519", "keyId": digest.SHA256(publicKey), "value": base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signed))},
	})
	grantPath := writeBundleFile(t, root, request.StageID+"-grant.json", envelope)
	keyPath := writeBundleFile(t, root, request.StageID+"-authority.pub", []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"))
	return StageAuthorizationSource{GrantPath: grantPath, PublicKeyPath: keyPath, EvaluationTime: time.Date(2026, 8, 18, 8, 5, 0, 0, time.UTC)}, nil
}
