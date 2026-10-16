package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/runnerprofile"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

type clusterIntentPlanArtifacts struct {
	SemanticDigest, RawDigest string
	Files                     map[string]string
	Expected                  stageplan.Expected
	EnablementObject          projection.ResourceIdentity
	TargetAccessObjects       []projection.ResourceIdentity
	NetworkProfileDigest      string
}

func bindClusterIntentStages(material clusterIntentMaterialized, recipe runnerprofile.Recipe, fixture, policyDigest, e, p string) (clusterIntentPlanArtifacts, error) {
	b := material.Binding
	rendered, err := recipe.Render(b.Identity, b.IntentRevision, fixture)
	if err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	files := rendered.Files
	// These are fresh static requirements, never runtime material or outcomes.
	lifecycle := map[string]any{"format": "ok141-lifecycle-observation-policy/v1", "intentRevision": b.IntentRevision,
		"expectedControlPlaneReplicas": 1, "expectedWorkerReplicas": 1, "pollIntervalSeconds": 15, "pollTimeoutSeconds": 1800, "failClosedOnStaleGeneration": true}
	runtime := map[string]any{"format": "ok-cli-runtime-binding-requirements/v1", "authorizationState": "NO-GO",
		"contractIdentity": b.Identity, "intentRevision": b.IntentRevision, "executionFixture": fixture,
		"workloadIdentityMode": "capi-cluster-uid/v1", "runnerIdentityMode": "bounded-job/v1", "requiresVerifiedReceiptPrefix": true}
	for name, doc := range map[string]any{"lifecycle-observation.json": lifecycle, "runtime-binding-requirements.json": runtime} {
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return clusterIntentPlanArtifacts{}, err
		}
		files[name] = append(raw, '\n')
	}
	fileDigests := map[string]string{}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := writeStaticBindingFile(filepath.Join(material.Output, name), files[name]); err != nil {
			return clusterIntentPlanArtifacts{}, err
		}
		fileDigests[name] = digest.SHA256(files[name])
	}
	if _, err := submission.LoadProviderAccessPolicy(filepath.Join(material.Output, "provider-access-policy.json"), submission.ProviderAccessExpected{
		PolicyDigest: policyDigest, ContractIdentity: b.Identity, IntentRevision: b.IntentRevision, ExecutionFixture: fixture,
		ManagementAuthority: b.Projection.ManagementPlane.Identity, ProviderAuthority: b.Projection.InfrastructurePlane.Identity,
	}); err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	if _, err := submission.LoadEnablement(filepath.Join(material.Output, "enablement.yaml"), submission.EnablementExpected{
		ArtifactDigest: fileDigests["enablement.yaml"], ContractIdentity: b.Identity, IntentRevision: b.IntentRevision, EnablementRevision: e,
		ExecutionFixture: fixture, ManagementAuthority: b.Projection.ManagementPlane.Identity, ObjectIdentity: rendered.EnablementObject,
	}); err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	if _, err := runner.LoadNetworkProfileFile(runner.NetworkProfileFileConfig{Path: filepath.Join(material.Output, "network-profile.json"),
		ExpectedProfileDigest: rendered.NetworkProfileDigest, ExpectedIntentRevision: b.IntentRevision, ExpectedEnablementRevision: e,
	}); err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	target := runner.FullRunStaticTargetIdentityDigest()
	if _, err := submission.LoadTargetAccess(filepath.Join(material.Output, "target-access.yaml"), submission.TargetAccessExpected{
		ArtifactDigest: fileDigests["target-access.yaml"], ContractIdentity: b.Identity, IntentRevision: b.IntentRevision, PlatformRevision: p, ExecutionFixture: fixture,
		TargetIdentityDigest: target, WorkloadAuthority: target, Objects: rendered.TargetAccessObjects,
	}); err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	inputs := map[string]string{"stage.provider-access": policyDigest, "stage.lifecycle-observation": fileDigests["lifecycle-observation.json"],
		"stage.enablement": fileDigests["enablement.yaml"], "stage.network-observation": rendered.NetworkProfileDigest,
		"stage.runtime-binding": fileDigests["runtime-binding-requirements.json"], "stage.target-access": fileDigests["target-access.yaml"]}
	for _, a := range b.Projection.Artifacts {
		switch a.Name {
		case "ok-infra-prerequisites.yaml":
			inputs["projection.provider-prerequisites"] = a.Digest
		case "ok-mgmt-lifecycle.yaml":
			inputs["projection.cluster-lifecycle"] = a.Digest
		}
	}
	expected := stageplan.Expected{ContractIdentity: b.Identity, IntentRevision: b.IntentRevision, EnablementRevision: e, PlatformRevision: p, ExecutionFixture: fixture,
		InfrastructureAuthority: b.Projection.InfrastructurePlane.Identity, ManagementAuthority: b.Projection.ManagementPlane.Identity, GitOpsAuthority: recipe.GitOpsAuthority(), CompletionMode: stageplan.CompletionModeBareClusterMVP}
	planRaw, plan, err := stageplan.BuildBareCluster(expected, inputs)
	if err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	if len(plan.Stages) != 7 {
		return clusterIntentPlanArtifacts{}, errors.New("fresh MVP plan did not preserve seven stages")
	}
	verifiedRaw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return clusterIntentPlanArtifacts{}, err
	}
	for name, raw := range map[string][]byte{"staged-plan.json": planRaw, "verified-staged-plan.json": append(verifiedRaw, '\n')} {
		if err := writeStaticBindingFile(filepath.Join(material.Output, name), raw); err != nil {
			return clusterIntentPlanArtifacts{}, err
		}
		fileDigests[name] = digest.SHA256(raw)
	}
	loaded, err := stageplan.Load(filepath.Join(material.Output, "staged-plan.json"), expected)
	if err != nil || loaded.PlanDigest != plan.PlanDigest {
		return clusterIntentPlanArtifacts{}, errors.New("persisted plan verification failed; partial output retained")
	}
	return clusterIntentPlanArtifacts{SemanticDigest: plan.PlanDigest, RawDigest: digest.SHA256(planRaw), Files: fileDigests,
		Expected: expected, EnablementObject: rendered.EnablementObject, TargetAccessObjects: rendered.TargetAccessObjects, NetworkProfileDigest: rendered.NetworkProfileDigest}, nil
}
