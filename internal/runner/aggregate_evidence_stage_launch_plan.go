package runner

import "errors"

const AggregateEvidenceStageLaunchPlanFormat = "ok147-aggregate-evidence-stage-launch-plan/v1"

// AggregateEvidenceStageLaunchPlan binds every exact object needed to start
// the final evaluator. The durable runtime-binding Secret is preflight-only.
type AggregateEvidenceStageLaunchPlan struct {
	Format                    string                           `json:"format"`
	State                     string                           `json:"state"`
	StageID                   string                           `json:"stageId"`
	Authority                 string                           `json:"authority"`
	EvidencePackageDigest     string                           `json:"evidencePackageDigest"`
	CredentialPackageDigest   string                           `json:"credentialPackageDigest"`
	PrivateInputPackageDigest string                           `json:"privateInputPackageDigest"`
	RuntimeManifestDigest     string                           `json:"runtimeManifestDigest"`
	PreflightBarrier          string                           `json:"preflightBarrier"`
	Preflights                []SubmissionStageLaunchPreflight `json:"preflights"`
	Creates                   []SubmissionStageLaunchCreate    `json:"creates"`
	MutationAllowed           bool                             `json:"mutationAllowed"`
}

// PlanAggregateEvidenceStageLaunch accepts only four coherent verified
// components. All ten GETs must pass before any of the nine create candidates
// can be considered by a later single-use launcher.
func PlanAggregateEvidenceStageLaunch(packaged VerifiedAggregateEvidenceStagePackage, credentials VerifiedAggregateEvidenceStageCredentialPackage, privateInputs VerifiedAggregateEvidenceStagePrivateInputPackage, runtime VerifiedAggregateEvidenceStageRuntimePrerequisite) (AggregateEvidenceStageLaunchPlan, error) {
	stage, err := PlanAggregateEvidenceStageInstallation(packaged)
	if err != nil {
		return AggregateEvidenceStageLaunchPlan{}, err
	}
	credentialReceipt, credentialObjects, err := prepareAggregateEvidenceStageCredentialInstallation(credentials)
	if err != nil {
		return AggregateEvidenceStageLaunchPlan{}, err
	}
	privateReceipt, err := privateInputs.Receipt()
	if err != nil {
		return AggregateEvidenceStageLaunchPlan{}, err
	}
	if err := verifyAggregateEvidenceStageRuntimePrerequisite(runtime); err != nil {
		return AggregateEvidenceStageLaunchPlan{}, err
	}
	if stage.EvidencePackageDigest != credentialReceipt.StagePackageDigest || stage.EvidencePackageDigest != privateReceipt.EvidencePackageDigest || stage.EvidencePackageDigest != runtime.receipt.EvidencePackageDigest || stage.StageID != credentialReceipt.StageID || stage.StageID != privateReceipt.StageID || stage.Authority != credentialReceipt.InstallationAuthority || stage.Authority != privateReceipt.Authority || stage.Authority != runtime.receipt.Authority {
		return AggregateEvidenceStageLaunchPlan{}, errors.New("aggregate evidence launch components do not share one verified identity")
	}

	preflights := make([]SubmissionStageLaunchPreflight, 0, 10)
	creates := make([]SubmissionStageLaunchCreate, 0, 9)
	appendCreate := func(order int, phase, apiVersion, kind, namespace, name, objectPath, collectionPath, objectDigest, existingPolicy, createPolicy string) {
		preflights = append(preflights, SubmissionStageLaunchPreflight{
			Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			Method: "GET", ObjectPath: objectPath, ResponseMode: "FULL_OBJECT", ExistingPolicy: existingPolicy,
			ObjectDigest: objectDigest,
		})
		creates = append(creates, SubmissionStageLaunchCreate{
			Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			Method: "POST", CollectionPath: collectionPath, CreatePolicy: createPolicy, ObjectDigest: objectDigest,
		})
	}
	runtimeCollection := "/api/v1/namespaces/" + runtime.receipt.Namespace + "/serviceaccounts"
	appendCreate(1, "runtime", "v1", "ServiceAccount", runtime.receipt.Namespace, runtime.receipt.Name,
		runtimeCollection+"/"+runtime.receipt.Name, runtimeCollection, runtime.receipt.ObjectDigest,
		"VERIFY_EXACT", "CREATE_IF_ABSENT_OR_VERIFY_EXISTING")

	secretCollection := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
	runtimeInput := privateReceipt.Objects[0]
	preflights = append(preflights, SubmissionStageLaunchPreflight{
		Order: 2, Phase: "private-runtime", APIVersion: "v1", Kind: "Secret",
		Namespace: runtimeInput.Namespace, Name: runtimeInput.Name, Method: "GET",
		ObjectPath: secretCollection + "/" + runtimeInput.Name, ResponseMode: "FULL_OBJECT",
		ExistingPolicy: runtimeInput.ExistingPolicy, ObjectDigest: runtimeInput.ObjectDigest,
	})
	for index, object := range stage.Creates[:2] {
		appendCreate(index+3, "stage-prerequisites", object.APIVersion, object.Kind, object.Namespace, object.Name,
			object.ObjectPath, object.CollectionPath, object.ObjectDigest,
			"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")
	}
	for index, object := range credentialObjects {
		appendCreate(index+5, "credentials", "v1", "Secret", submissionStageInputNamespace, object.name,
			object.objectPath, object.collectionPath, object.objectDigest,
			"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")
	}
	capability := privateReceipt.Objects[1]
	appendCreate(9, "private-capability", "v1", "Secret", capability.Namespace, capability.Name,
		secretCollection+"/"+capability.Name, secretCollection, capability.ObjectDigest,
		capability.ExistingPolicy, capability.CreatePolicy)
	job := stage.Creates[2]
	appendCreate(10, "job", job.APIVersion, job.Kind, job.Namespace, job.Name,
		job.ObjectPath, job.CollectionPath, job.ObjectDigest,
		"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")

	return AggregateEvidenceStageLaunchPlan{
		Format: AggregateEvidenceStageLaunchPlanFormat, State: "VERIFIED", StageID: stage.StageID,
		Authority: stage.Authority, EvidencePackageDigest: stage.EvidencePackageDigest,
		CredentialPackageDigest: credentialReceipt.PackageDigest, PrivateInputPackageDigest: privateReceipt.PackageDigest,
		RuntimeManifestDigest: runtime.receipt.ManifestDigest,
		PreflightBarrier:      "RUNTIME_BINDING_REQUIRED_THEN_ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT",
		Preflights:            preflights, Creates: creates, MutationAllowed: false,
	}, nil
}
