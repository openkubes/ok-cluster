package runner

import "errors"

const RuntimeBindingStageLaunchPlanFormat = "ok147-runtime-binding-stage-launch-plan/v1"

// RuntimeBindingStageLaunchPlan binds all seven exact objects needed for one
// runtime-binding Job launch. It contains no body or credential and grants no
// mutation authority.
type RuntimeBindingStageLaunchPlan struct {
	Format                  string                           `json:"format"`
	State                   string                           `json:"state"`
	StageID                 string                           `json:"stageId"`
	Authority               string                           `json:"authority"`
	StagePackageDigest      string                           `json:"stagePackageDigest"`
	CredentialPackageDigest string                           `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string                           `json:"runtimeManifestDigest"`
	PreflightBarrier        string                           `json:"preflightBarrier"`
	Preflights              []SubmissionStageLaunchPreflight `json:"preflights"`
	Creates                 []SubmissionStageLaunchCreate    `json:"creates"`
	MutationAllowed         bool                             `json:"mutationAllowed"`
}

// PlanRuntimeBindingStageLaunch accepts only one coherent stage package,
// three-credential package and tokenless runtime prerequisite. Every GET must
// pass before any create can be considered by a later launcher.
func PlanRuntimeBindingStageLaunch(packaged VerifiedRuntimeBindingStagePackage, credentials VerifiedRuntimeBindingStageCredentialPackage, runtime VerifiedRuntimeBindingStageRuntimePrerequisite) (RuntimeBindingStageLaunchPlan, error) {
	stage, err := PlanRuntimeBindingStageInstallation(packaged)
	if err != nil {
		return RuntimeBindingStageLaunchPlan{}, err
	}
	if err := verifyRuntimeBindingStageCredentialPackage(credentials); err != nil {
		return RuntimeBindingStageLaunchPlan{}, err
	}
	runtimeReceipt, err := runtime.Receipt()
	if err != nil {
		return RuntimeBindingStageLaunchPlan{}, err
	}
	if stage.StagePackageDigest != credentials.receipt.StagePackageDigest || stage.StagePackageDigest != runtimeReceipt.BindingPackageDigest || stage.StageID != credentials.receipt.StageID || stage.Authority != credentials.installationAuthority || stage.Authority != runtimeReceipt.Authority || credentials.receipt.WorkloadBindingDigest != packaged.receipt.WorkloadBindingDigest {
		return RuntimeBindingStageLaunchPlan{}, errors.New("runtime binding launch components do not share one verified identity")
	}

	preflights := make([]SubmissionStageLaunchPreflight, 0, 7)
	creates := make([]SubmissionStageLaunchCreate, 0, 7)
	appendObject := func(order int, phase, apiVersion, kind, namespace, name, objectPath, collectionPath, objectDigest, existingPolicy, createPolicy string) {
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
	runtimeCollection := "/api/v1/namespaces/" + runtimeReceipt.Namespace + "/serviceaccounts"
	appendObject(1, "runtime", "v1", "ServiceAccount", runtimeReceipt.Namespace, runtimeReceipt.Name,
		runtimeCollection+"/"+runtimeReceipt.Name, runtimeCollection, runtimeReceipt.ObjectDigest,
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
	appendObject(7, "job", job.APIVersion, job.Kind, job.Namespace, job.Name,
		job.ObjectPath, job.CollectionPath, job.ObjectDigest,
		"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")

	return RuntimeBindingStageLaunchPlan{
		Format: RuntimeBindingStageLaunchPlanFormat, State: "VERIFIED", StageID: stage.StageID,
		Authority: stage.Authority, StagePackageDigest: stage.StagePackageDigest,
		CredentialPackageDigest: credentials.receipt.PackageDigest, RuntimeManifestDigest: runtimeReceipt.ManifestDigest,
		PreflightBarrier: "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT", Preflights: preflights, Creates: creates,
		MutationAllowed: false,
	}, nil
}
