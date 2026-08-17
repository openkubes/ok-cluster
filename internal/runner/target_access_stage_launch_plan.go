package runner

import "errors"

const TargetAccessStageLaunchPlanFormat = "ok147-target-access-stage-launch-plan/v1"

// TargetAccessStageLaunchPlan binds every exact execution-plane object needed
// to start the Job. It contains no object or credential bytes.
type TargetAccessStageLaunchPlan struct {
	Format                    string                           `json:"format"`
	State                     string                           `json:"state"`
	StageID                   string                           `json:"stageId"`
	Authority                 string                           `json:"authority"`
	TargetAccessPackageDigest string                           `json:"targetAccessPackageDigest"`
	CredentialPackageDigest   string                           `json:"credentialPackageDigest"`
	RuntimeManifestDigest     string                           `json:"runtimeManifestDigest"`
	PreflightBarrier          string                           `json:"preflightBarrier"`
	Preflights                []SubmissionStageLaunchPreflight `json:"preflights"`
	Creates                   []SubmissionStageLaunchCreate    `json:"creates"`
	MutationAllowed           bool                             `json:"mutationAllowed"`
}

// PlanTargetAccessStageLaunch requires one coherent stage, credential package
// and runtime prerequisite. Every GET must complete before the first POST.
func PlanTargetAccessStageLaunch(packaged VerifiedTargetAccessStagePackage, credentials VerifiedTargetAccessStageCredentialPackage, runtime VerifiedTargetAccessStageRuntimePrerequisite) (TargetAccessStageLaunchPlan, error) {
	stage, err := PlanTargetAccessStageInstallation(packaged)
	if err != nil {
		return TargetAccessStageLaunchPlan{}, err
	}
	if err := verifyTargetAccessStageCredentialPackage(credentials); err != nil {
		return TargetAccessStageLaunchPlan{}, err
	}
	if err := verifyTargetAccessStageRuntimePrerequisite(runtime); err != nil {
		return TargetAccessStageLaunchPlan{}, err
	}
	if stage.StagePackageDigest != credentials.receipt.TargetAccessPackageDigest || stage.StagePackageDigest != runtime.receipt.TargetAccessPackageDigest || stage.StageID != credentials.receipt.StageID || stage.Authority != credentials.installationAuthority || stage.Authority != runtime.receipt.Authority {
		return TargetAccessStageLaunchPlan{}, errors.New("target-access launch components do not share one verified identity")
	}

	preflights := make([]SubmissionStageLaunchPreflight, 0, 6)
	creates := make([]SubmissionStageLaunchCreate, 0, 6)
	appendObject := func(order int, phase, apiVersion, kind, namespace, name, objectPath, collectionPath, objectDigest, existingPolicy, createPolicy string) {
		preflights = append(preflights, SubmissionStageLaunchPreflight{
			Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			Method: "GET", ObjectPath: objectPath, ResponseMode: "FULL_OBJECT", ExistingPolicy: existingPolicy, ObjectDigest: objectDigest,
		})
		creates = append(creates, SubmissionStageLaunchCreate{
			Order: order, Phase: phase, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			Method: "POST", CollectionPath: collectionPath, CreatePolicy: createPolicy, ObjectDigest: objectDigest,
		})
	}
	runtimeCollection := "/api/v1/namespaces/" + runtime.receipt.Namespace + "/serviceaccounts"
	appendObject(1, "runtime", "v1", "ServiceAccount", runtime.receipt.Namespace, runtime.receipt.Name,
		runtimeCollection+"/"+runtime.receipt.Name, runtimeCollection, runtime.receipt.ObjectDigest,
		"VERIFY_EXACT", "CREATE_IF_ABSENT_OR_VERIFY_EXISTING")
	for index, object := range stage.Creates[:2] {
		appendObject(index+2, "stage-prerequisites", object.APIVersion, object.Kind, object.Namespace, object.Name,
			object.ObjectPath, object.CollectionPath, object.ObjectDigest,
			"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")
	}
	for index, object := range credentials.objects {
		collection := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
		appendObject(index+4, "credentials", "v1", "Secret", submissionStageInputNamespace, object.name,
			collection+"/"+object.name, collection, credentials.receipt.Credentials[index].ObjectDigest,
			"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")
	}
	job := stage.Creates[2]
	appendObject(6, "job", job.APIVersion, job.Kind, job.Namespace, job.Name,
		job.ObjectPath, job.CollectionPath, job.ObjectDigest,
		"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")

	return TargetAccessStageLaunchPlan{
		Format: TargetAccessStageLaunchPlanFormat, State: "VERIFIED", StageID: stage.StageID,
		Authority: stage.Authority, TargetAccessPackageDigest: stage.StagePackageDigest,
		CredentialPackageDigest: credentials.receipt.PackageDigest, RuntimeManifestDigest: runtime.receipt.ManifestDigest,
		PreflightBarrier: "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT", Preflights: preflights, Creates: creates,
		MutationAllowed: false,
	}, nil
}
