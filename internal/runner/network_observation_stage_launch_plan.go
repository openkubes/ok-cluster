package runner

import "errors"

const NetworkObservationStageLaunchPlanFormat = "ok147-network-observation-stage-launch-plan/v1"

// NetworkObservationStageLaunchPlan binds all seven exact objects needed for
// one Job launch. It contains no object body or credential and grants no
// mutation authority.
type NetworkObservationStageLaunchPlan struct {
	Format                   string                           `json:"format"`
	State                    string                           `json:"state"`
	StageID                  string                           `json:"stageId"`
	Authority                string                           `json:"authority"`
	ObservationPackageDigest string                           `json:"observationPackageDigest"`
	CredentialPackageDigest  string                           `json:"credentialPackageDigest"`
	RuntimeManifestDigest    string                           `json:"runtimeManifestDigest"`
	PreflightBarrier         string                           `json:"preflightBarrier"`
	Preflights               []SubmissionStageLaunchPreflight `json:"preflights"`
	Creates                  []SubmissionStageLaunchCreate    `json:"creates"`
	MutationAllowed          bool                             `json:"mutationAllowed"`
}

// PlanNetworkObservationStageLaunch accepts only a coherent package,
// three-credential package and tokenless runtime prerequisite. Every GET must
// pass before any create can be considered by a later launcher.
func PlanNetworkObservationStageLaunch(packaged VerifiedNetworkObservationStagePackage, credentials VerifiedNetworkObservationStageCredentialPackage, runtime VerifiedNetworkObservationStageRuntimePrerequisite) (NetworkObservationStageLaunchPlan, error) {
	stage, err := PlanNetworkObservationStageInstallation(packaged)
	if err != nil {
		return NetworkObservationStageLaunchPlan{}, err
	}
	if err := verifyNetworkObservationStageCredentialPackage(credentials); err != nil {
		return NetworkObservationStageLaunchPlan{}, err
	}
	if err := verifyNetworkObservationStageRuntimePrerequisite(runtime); err != nil {
		return NetworkObservationStageLaunchPlan{}, err
	}
	if stage.ObservationPackageDigest != credentials.receipt.ObservationPackageDigest || stage.ObservationPackageDigest != runtime.receipt.ObservationPackageDigest || stage.StageID != credentials.receipt.StageID || stage.Authority != credentials.installationAuthority || stage.Authority != runtime.receipt.Authority || credentials.receipt.WorkloadBindingDigest != packaged.receipt.WorkloadBindingDigest {
		return NetworkObservationStageLaunchPlan{}, errors.New("network observation launch components do not share one verified identity")
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
	appendObject(7, "job", job.APIVersion, job.Kind, job.Namespace, job.Name,
		job.ObjectPath, job.CollectionPath, job.ObjectDigest,
		"VERIFY_EXACT_GLOBAL_STATE", "CREATE_ONLY_AFTER_GLOBAL_ABSENCE")

	return NetworkObservationStageLaunchPlan{
		Format: NetworkObservationStageLaunchPlanFormat, State: "VERIFIED", StageID: stage.StageID,
		Authority: stage.Authority, ObservationPackageDigest: stage.ObservationPackageDigest,
		CredentialPackageDigest: credentials.receipt.PackageDigest, RuntimeManifestDigest: runtime.receipt.ManifestDigest,
		PreflightBarrier: "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT", Preflights: preflights, Creates: creates,
		MutationAllowed: false,
	}, nil
}
