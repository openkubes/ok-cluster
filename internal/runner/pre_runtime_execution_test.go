package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

func TestPreRuntimeExecutionComposesExactPrefixWithDynamicAuthorization(t *testing.T) {
	config, factories, calls, requests := preRuntimeExecutionFixture(t)
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err != nil {
		t.Fatalf("%v requests=%#v calls=%v", err, *requests, *calls)
	}
	if receipt.Format != PreRuntimeExecutionReceiptFormat || receipt.State != "SUCCEEDED" || receipt.StoppedAt != "" ||
		len(receipt.Checkpoints) != 7 || len(receipt.ResolvedAuthorizations) != 4 {
		t.Fatalf("unexpected pre-runtime execution receipt: %#v", receipt)
	}
	if !reflect.DeepEqual(*calls, preRuntimeStageOrder) {
		t.Fatalf("pre-runtime execution order differs: %v", *calls)
	}
	wantAuthorized := []string{"provider-prerequisites", "cluster-lifecycle", "enablement", "target-access"}
	if len(*requests) != len(wantAuthorized) {
		t.Fatalf("authorization count differs: %#v", *requests)
	}
	for index, stageID := range wantAuthorized {
		if (*requests)[index].StageID != stageID || len((*requests)[index].Predecessors) != minInt(index, 1) {
			t.Fatalf("authorization %d differs: %#v", index, (*requests)[index])
		}
	}
	for _, stageID := range preRuntimeStageOrder {
		path := filepath.Join(config.ReceiptDirectory, preRuntimeReceiptFiles[stageID])
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("receipt %s was not persisted privately: %#v %v", stageID, info, statErr)
		}
	}
	for _, path := range []string{config.RuntimeBinding.OutputPath, config.RuntimeBindingReceiptPath} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("runtime binding handoff was not persisted privately: %s %#v %v", path, info, statErr)
		}
	}
	if _, err := LoadRuntimeBindingMaterialFiles(RuntimeBindingMaterialFileConfig{
		Bundle:       StageResumeConfig{PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: mustReceiptPrefix(t, executor)},
		MaterialPath: config.RuntimeBinding.OutputPath, ReceiptPath: config.RuntimeBindingReceiptPath,
	}); err != nil {
		t.Fatalf("completed runtime binding handoff is not replayable: %v", err)
	}
	prefix, err := executor.ReceiptPrefix()
	if err != nil || len(prefix) != 7 {
		t.Fatalf("completed private prefix is unavailable: %#v %v", prefix, err)
	}
	targetIdentity, err := executor.RuntimeTargetIdentity()
	if err != nil || targetIdentity != digest.SHA256([]byte("11111111-1111-4111-8111-111111111111")) {
		t.Fatalf("completed runtime target identity differs: %q %v", targetIdentity, err)
	}
	workloadAuthority, err := executor.RuntimeWorkloadAuthority()
	if err != nil || workloadAuthority.Path != config.NetworkObservation.Workload.Path ||
		workloadAuthority.TokenFile != config.NetworkObservation.Workload.TokenFile ||
		workloadAuthority.CAFile != config.NetworkObservation.Workload.CAFile || workloadAuthority.ExpectedBindingDigest == "" {
		t.Fatalf("completed workload authority differs: %#v %v", workloadAuthority, err)
	}
	prefix[0].Digest = runnerStageSHA("f")
	again, err := executor.ReceiptPrefix()
	if err != nil || again[0].Digest == prefix[0].Digest {
		t.Fatal("private receipt prefix was not defensively copied")
	}
	if second, err := executor.Run(context.Background()); err == nil || second.State != "STOPPED" || len(*calls) != 7 {
		t.Fatalf("single-use executor ran twice: %#v calls=%v err=%v", second, *calls, err)
	}
	public := mustJSON(t, receipt)
	for _, forbidden := range []string{
		config.ReceiptDirectory, config.RuntimeBinding.OutputPath, config.RuntimeBindingReceiptPath,
		"token", "endpoint", "kubeconfig",
	} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("public pre-runtime receipt exposed %q", forbidden)
		}
	}
}

func TestPreRuntimeExecutionStopsBeforeNetworkWhenWorkloadAuthorityIsUnavailable(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		return WorkloadAuthorityFileResolverConfig{}, errors.New("private workload authority unavailable")
	})
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "network-observation" || len(receipt.Checkpoints) != 4 ||
		!reflect.DeepEqual(*calls, preRuntimeStageOrder[:4]) {
		t.Fatalf("missing workload authority crossed Stage 5: %#v calls=%v err=%v", receipt, *calls, err)
	}
	if _, err := executor.RuntimeWorkloadAuthority(); err == nil {
		t.Fatal("partial execution exposed workload authority")
	}
}

func TestPreRuntimeExecutionRejectsWorkloadAuthorityOutsideBoundDestinations(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(context.Context, StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		return WorkloadAuthorityFileResolverConfig{
			Path:                  filepath.Join(filepath.Dir(config.NetworkObservation.Workload.Path), "foreign-binding.json"),
			ExpectedBindingDigest: runnerStageSHA("c"), TokenFile: config.NetworkObservation.Workload.TokenFile,
			CAFile: config.NetworkObservation.Workload.CAFile,
		}, nil
	})
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "network-observation" || len(receipt.Checkpoints) != 4 ||
		!reflect.DeepEqual(*calls, preRuntimeStageOrder[:4]) {
		t.Fatalf("foreign workload destination crossed Stage 5: %#v calls=%v err=%v", receipt, *calls, err)
	}
}

func TestPreRuntimeExecutionStopsAfterDurableReceiptWhenNextGrantIsUnavailable(t *testing.T) {
	config, factories, calls, requests := preRuntimeExecutionFixture(t)
	resolved := config.Authorization
	config.Authorization = StageAuthorizationResolverFunc(func(ctx context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
		if request.StageID == "cluster-lifecycle" {
			*requests = append(*requests, cloneStageAuthorizationRequest(request))
			return StageAuthorizationSource{}, errors.New("private authority failure")
		}
		return resolved.ResolveStageAuthorization(ctx, request)
	})
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "cluster-lifecycle" || len(receipt.Checkpoints) != 1 || len(*calls) != 1 {
		t.Fatalf("authority stop did not preserve exact prefix: %#v calls=%v err=%v", receipt, *calls, err)
	}
	if _, err := os.Lstat(filepath.Join(config.ReceiptDirectory, preRuntimeReceiptFiles["provider-prerequisites"])); err != nil {
		t.Fatal("successful provider receipt was not retained")
	}
	if _, err := executor.ReceiptPrefix(); err == nil {
		t.Fatal("partial prefix was exposed as complete")
	}
}

func TestPreRuntimeExecutionStopsWithoutReplayWhenReceiptPersistenceFails(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	persistCalls := 0
	factories.persist = func(context.Context, StageResumeConfig, *ledger.Ledger, StageRunReceiptReference, string) (StageReceiptSource, error) {
		persistCalls++
		return StageReceiptSource{}, errors.New("private persistence failure")
	}
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "provider-prerequisites" || len(receipt.Checkpoints) != 1 ||
		!reflect.DeepEqual(*calls, []string{"provider-prerequisites"}) || persistCalls != 1 {
		t.Fatalf("persistence stop replayed or lost durable stage identity: %#v calls=%v persist=%d err=%v", receipt, *calls, persistCalls, err)
	}
	if _, err := executor.ReceiptPrefix(); err == nil {
		t.Fatal("unpersisted prefix was exposed")
	}
}

func TestPreRuntimeExecutionStopsAfterStageSixWhenMaterialReceiptDiffers(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	original := factories.binding
	factories.binding = func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeBindingInvocation, error) {
		invocation, err := original(resume, config)
		if err != nil {
			return preRuntimeBindingInvocation{}, err
		}
		valid := invocation.materialReceipt
		invocation.materialReceipt = func() (RuntimeBindingMaterialReceipt, error) {
			receipt, receiptErr := valid()
			receipt.PrivateMaterialDigest = runnerStageSHA("f")
			return receipt, receiptErr
		}
		return invocation, nil
	}
	executor, err := openPreRuntimeExecution(config, factories)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := executor.Run(context.Background())
	if err == nil || receipt.State != "STOPPED" || receipt.StoppedAt != "runtime-binding" || len(receipt.Checkpoints) != 6 ||
		!reflect.DeepEqual(*calls, preRuntimeStageOrder[:6]) {
		t.Fatalf("material-receipt mismatch crossed Stage 6: %#v calls=%v err=%v", receipt, *calls, err)
	}
	if _, statErr := os.Lstat(config.RuntimeBindingReceiptPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid material receipt was persisted: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(config.ReceiptDirectory, preRuntimeReceiptFiles["runtime-binding"])); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("public Stage-6 receipt crossed failed private handoff: %v", statErr)
	}
}

func TestOpenPreRuntimeExecutionRejectsUnsafeReceiptDestination(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	if err := os.Chmod(config.ReceiptDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openPreRuntimeExecution(config, factories); err == nil || len(*calls) != 0 {
		t.Fatalf("unsafe receipt directory was accepted: calls=%v err=%v", *calls, err)
	}
}

func TestOpenPreRuntimeExecutionRejectsPreboundWorkloadIdentity(t *testing.T) {
	config, factories, calls, _ := preRuntimeExecutionFixture(t)
	prebound := config.NetworkObservation.Workload
	prebound.ExpectedBindingDigest = runnerStageSHA("d")
	config.NetworkObservation.Workload = prebound
	config.RuntimeBinding.Workload = prebound
	config.TargetAccess.Runtime.Workload = prebound
	if _, err := openPreRuntimeExecution(config, factories); err == nil || len(*calls) != 0 {
		t.Fatalf("caller-selected workload identity was accepted: calls=%v err=%v", *calls, err)
	}
}

func TestBindingStageReceiptReferenceRetainsExactPublicIdentity(t *testing.T) {
	receipt := execution.BindingStageRunReceipt{
		Format: execution.BindingStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: runnerStageSHA("a"),
		StageID: "runtime-binding", StageReceiptDigest: runnerStageSHA("6"),
	}
	reference := BindingStageReceiptReference(receipt)
	if reference.Format != receipt.Format || reference.State != receipt.State || reference.PlanDigest != receipt.PlanDigest ||
		reference.StageID != receipt.StageID || reference.StageReceiptDigest != receipt.StageReceiptDigest {
		t.Fatalf("binding receipt reference differs: %#v", reference)
	}
}

func preRuntimeExecutionFixture(t *testing.T) (PreRuntimeExecutionConfig, preRuntimeExecutionFactories, *[]string, *[]StageAuthorizationRequest) {
	t.Helper()
	base := submissionBundleFixture(t, false, "")
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
	resolver := StageAuthorizationResolverFunc(func(_ context.Context, request StageAuthorizationRequest) (StageAuthorizationSource, error) {
		requests = append(requests, cloneStageAuthorizationRequest(request))
		return writeResolvedStageGrant(t, grantDirectory, request)
	})
	config := PreRuntimeExecutionConfig{
		PlanPath: base.config.PlanPath, PlanExpected: base.config.PlanExpected,
		ProjectionManifestPath: base.config.ProjectionManifestPath, ProjectionRoot: base.config.ProjectionRoot,
		Authorization: resolver, ReceiptDirectory: receiptDirectory,
	}
	runtimeDirectory := t.TempDir()
	if err := os.Chmod(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	config.RuntimeBinding.OutputPath = filepath.Join(runtimeDirectory, "runtime-binding.json")
	config.RuntimeBindingReceiptPath = filepath.Join(runtimeDirectory, "runtime-binding-receipt.json")
	workloadAuthority := WorkloadAuthorityFileResolverConfig{
		Path:      filepath.Join(runtimeDirectory, "workload-authority.json"),
		TokenFile: filepath.Join(runtimeDirectory, "workload-token"),
		CAFile:    filepath.Join(runtimeDirectory, "workload-ca.crt"),
	}
	config.NetworkObservation.Workload = workloadAuthority
	config.RuntimeBinding.Workload = workloadAuthority
	config.TargetAccess.Runtime.Workload = workloadAuthority
	resolvedWorkloadAuthority := workloadAuthority
	resolvedWorkloadAuthority.ExpectedBindingDigest = runnerStageSHA("b")
	config.WorkloadAuthority = PreRuntimeWorkloadAuthorityResolverFunc(func(_ context.Context, resume StageResumeConfig) (WorkloadAuthorityFileResolverConfig, error) {
		decision, err := InspectStageResume(resume)
		if err != nil || decision.State != "NEXT" || decision.StageID != "network-observation" || len(resume.Receipts) != 4 {
			return WorkloadAuthorityFileResolverConfig{}, errors.New("workload authority resolved outside exact Stage-5 cursor")
		}
		return resolvedWorkloadAuthority, nil
	})
	store := &ledger.Ledger{}
	verified := map[string]stagereceipt.Verified{}
	makeReceipt := func(resume StageResumeConfig, stageID string) (stagereceipt.Verified, string) {
		plan, cursor, _, err := loadStageResumeWithPrefix(resume)
		if err != nil {
			t.Fatal(err)
		}
		predecessors, err := cursor.Predecessors()
		if err != nil {
			t.Fatal(err)
		}
		mutation, outcome := "NOT_APPLICABLE", ""
		if stageID == "provider-prerequisites" || stageID == "cluster-lifecycle" || stageID == "enablement" || stageID == "target-access" {
			mutation, outcome = "ATTEMPTED", digest.SHA256([]byte("operation-"+stageID))
		}
		at := time.Date(2026, 8, 18, 8, len(resume.Receipts), 0, 0, time.UTC)
		var stageReceipt stagereceipt.Verified
		if stageID == "cluster-lifecycle" {
			stageReceipt, err = stagereceipt.NewWithTargetClusterUIDDigest(plan, stageID, predecessors, "SUCCEEDED", mutation, outcome, digest.SHA256([]byte("evidence-"+stageID)), digest.SHA256([]byte("11111111-1111-4111-8111-111111111111")), at)
		} else {
			stageReceipt, err = stagereceipt.New(plan, stageID, predecessors, "SUCCEEDED", mutation, outcome, digest.SHA256([]byte("evidence-"+stageID)), at)
		}
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest, err := stageReceipt.Digest()
		if err != nil {
			t.Fatal(err)
		}
		verified[receiptDigest] = stageReceipt
		return stageReceipt, receiptDigest
	}
	staged := func(resume StageResumeConfig, stageID string) preRuntimeStagedInvocation {
		return preRuntimeStagedInvocation{store: store, run: func(context.Context) (execution.StagedOperationReceipt, error) {
			calls = append(calls, stageID)
			_, receiptDigest := makeReceipt(resume, stageID)
			return execution.StagedOperationReceipt{Format: execution.StagedReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: base.plan.PlanDigest, StageID: stageID, StageReceiptDigest: receiptDigest}, nil
		}}
	}
	observation := func(resume StageResumeConfig, stageID string) preRuntimeObservationInvocation {
		return preRuntimeObservationInvocation{store: store, run: func(context.Context) (execution.ObservationStageRunReceipt, error) {
			calls = append(calls, stageID)
			_, receiptDigest := makeReceipt(resume, stageID)
			return execution.ObservationStageRunReceipt{Format: execution.ObservationStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: base.plan.PlanDigest, StageID: stageID, StageReceiptDigest: receiptDigest}, nil
		}}
	}
	factories := preRuntimeExecutionFactories{
		submission: func(resume StageResumeConfig, stageID string, _ StageAuthorizationSource, _ PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			return staged(resume, stageID), nil
		},
		lifecycle: func(resume StageResumeConfig, _ PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error) {
			return observation(resume, "lifecycle-observation"), nil
		},
		enablement: func(resume StageResumeConfig, _ StageAuthorizationSource, _ PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			return staged(resume, "enablement"), nil
		},
		network: func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeObservationInvocation, error) {
			if config.NetworkObservation.Workload != resolvedWorkloadAuthority {
				return preRuntimeObservationInvocation{}, errors.New("network stage lacks resolved workload authority")
			}
			return observation(resume, "network-observation"), nil
		},
		binding: func(resume StageResumeConfig, config PreRuntimeExecutionConfig) (preRuntimeBindingInvocation, error) {
			if config.RuntimeBinding.Workload != resolvedWorkloadAuthority {
				return preRuntimeBindingInvocation{}, errors.New("runtime binding stage lacks resolved workload authority")
			}
			var materialReceipt RuntimeBindingMaterialReceipt
			return preRuntimeBindingInvocation{store: store, run: func(context.Context) (execution.BindingStageRunReceipt, error) {
				calls = append(calls, "runtime-binding")
				plan, _, prefix, err := loadStageResumeWithPrefix(resume)
				if err != nil {
					return execution.BindingStageRunReceipt{}, err
				}
				lifecycle, err := prefix[1].Receipt()
				if err != nil {
					return execution.BindingStageRunReceipt{}, err
				}
				network, err := prefix[4].Receipt()
				if err != nil {
					return execution.BindingStageRunReceipt{}, err
				}
				material := RuntimeBindingMaterial{
					Format: RuntimeBindingMaterialFormat, State: "CURRENT_RUNTIME_BOUND", PlanDigest: plan.PlanDigest,
					IntentRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
					PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
					Target: RuntimeBindingTarget{
						Name: plan.ContractIdentity.Name, CAPIClusterUID: "11111111-1111-4111-8111-111111111111",
						TargetIdentityScheme: "capi-cluster-uid", WorkloadAPIEndpoint: "https://runtime.invalid:6443",
						WorkloadAPICAData: "Y2E=", WorkloadAPICADigest: runnerStageSHA("a"),
						KubeSystemUID: "22222222-2222-4222-8222-222222222222",
					},
					Storage:  RuntimeBindingStorage{Name: "local-path", UID: "33333333-3333-4333-8333-333333333333", Provisioner: "rancher.io/local-path"},
					Evidence: RuntimeBindingEvidence{LifecycleEvidenceDigest: lifecycle.EvidenceDigest, NetworkEvidenceDigest: network.EvidenceDigest},
				}
				raw, err := canonicalRuntimeBinding(material)
				if err != nil {
					return execution.BindingStageRunReceipt{}, err
				}
				if err := os.WriteFile(config.RuntimeBinding.OutputPath, raw, 0o600); err != nil {
					return execution.BindingStageRunReceipt{}, err
				}
				materialReceipt = RuntimeBindingMaterialReceipt{
					Format: RuntimeBindingMaterialFormat, State: "VERIFIED", StageID: "runtime-binding", PlanDigest: plan.PlanDigest,
					IntentRevision: plan.IntentRevision, TargetClusterUIDDigest: digest.SHA256([]byte(material.Target.CAPIClusterUID)),
					WorkloadAPICADigest: material.Target.WorkloadAPICADigest, KubeSystemUIDDigest: digest.SHA256([]byte(material.Target.KubeSystemUID)),
					LocalPathStorageUIDDigest: digest.SHA256([]byte(material.Storage.UID)), LifecycleEvidenceDigest: lifecycle.EvidenceDigest,
					NetworkEvidenceDigest: network.EvidenceDigest, PrivateMaterialDigest: digest.SHA256(raw), PersistentMutationAllowed: false,
				}
				_, receiptDigest := makeReceipt(resume, "runtime-binding")
				return execution.BindingStageRunReceipt{Format: execution.BindingStageReceiptFormat, State: "COMPLETED_SUCCEEDED", PlanDigest: base.plan.PlanDigest, StageID: "runtime-binding", StageReceiptDigest: receiptDigest}, nil
			}, materialReceipt: func() (RuntimeBindingMaterialReceipt, error) {
				return materialReceipt, nil
			}}, nil
		},
		target: func(resume StageResumeConfig, _ StageAuthorizationSource, config PreRuntimeExecutionConfig) (preRuntimeStagedInvocation, error) {
			if config.TargetAccess.Runtime.Workload != resolvedWorkloadAuthority {
				return preRuntimeStagedInvocation{}, errors.New("target access stage lacks resolved workload authority")
			}
			return staged(resume, "target-access"), nil
		},
		persist: func(_ context.Context, _ StageResumeConfig, _ *ledger.Ledger, reference StageRunReceiptReference, path string) (StageReceiptSource, error) {
			stageReceipt, ok := verified[reference.StageReceiptDigest]
			if !ok {
				return StageReceiptSource{}, errors.New("test receipt is unavailable")
			}
			raw, err := stageReceipt.Bytes()
			if err != nil {
				return StageReceiptSource{}, err
			}
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return StageReceiptSource{}, err
			}
			if _, err = file.Write(raw); err != nil {
				file.Close()
				return StageReceiptSource{}, err
			}
			if err = file.Close(); err != nil {
				return StageReceiptSource{}, err
			}
			return StageReceiptSource{Path: path, Digest: reference.StageReceiptDigest}, nil
		},
	}
	return config, factories, &calls, &requests
}

func mustReceiptPrefix(t *testing.T, executor *PreRuntimeExecution) []StageReceiptSource {
	t.Helper()
	prefix, err := executor.ReceiptPrefix()
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

func minInt(first, second int) int {
	if first < second {
		return first
	}
	return second
}
