package runner

import "errors"

const SubmissionStageLaunchPlanFormat = "ok147-submission-stage-launch-plan/v2"

type SubmissionStageLaunchPreflight struct {
	Order          int    `json:"order"`
	Phase          string `json:"phase"`
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	Method         string `json:"method"`
	ObjectPath     string `json:"objectPath"`
	ResponseMode   string `json:"responseMode"`
	ExistingPolicy string `json:"existingPolicy"`
	ObjectDigest   string `json:"objectDigest"`
}

type SubmissionStageLaunchCreate struct {
	Order          int    `json:"order"`
	Phase          string `json:"phase"`
	APIVersion     string `json:"apiVersion"`
	Kind           string `json:"kind"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	Method         string `json:"method"`
	CollectionPath string `json:"collectionPath"`
	CreatePolicy   string `json:"createPolicy"`
	ObjectDigest   string `json:"objectDigest"`
}

// SubmissionStageLaunchPlan correlates every object needed to start one Job.
// It is non-mutating and contains no object body or credential content.
type SubmissionStageLaunchPlan struct {
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

// PlanSubmissionStageLaunch requires one coherent verified package,
// credential package and runtime prerequisite. Every GET in Preflights must
// pass before the first entry in Creates can be attempted.
func PlanSubmissionStageLaunch(packaged VerifiedSubmissionStagePackage, credentials VerifiedSubmissionStageCredentialPackage, runtime VerifiedSubmissionStageRuntimePrerequisite) (SubmissionStageLaunchPlan, error) {
	stage, err := PlanSubmissionStageInstallation(packaged)
	if err != nil {
		return SubmissionStageLaunchPlan{}, err
	}
	credentialReceipt, credentialObjects, err := prepareSubmissionStageCredentialInstallation(credentials)
	if err != nil {
		return SubmissionStageLaunchPlan{}, err
	}
	if err := verifySubmissionStageRuntimePrerequisite(runtime); err != nil {
		return SubmissionStageLaunchPlan{}, err
	}
	if stage.PackageDigest != credentialReceipt.StagePackageDigest || stage.PackageDigest != runtime.receipt.StagePackageDigest || stage.StageID != credentialReceipt.StageID || packaged.installationAuthority != credentials.installationAuthority || packaged.installationAuthority != runtime.receipt.Authority || credentialReceipt.InstallationAuthority != packaged.installationAuthority {
		return SubmissionStageLaunchPlan{}, errors.New("submission stage launch components do not share one verified identity")
	}

	preflights := make([]SubmissionStageLaunchPreflight, 0, 6)
	creates := make([]SubmissionStageLaunchCreate, 0, 6)
	runtimeCollection := "/api/v1/namespaces/" + runtime.receipt.Namespace + "/serviceaccounts"
	preflights = append(preflights, SubmissionStageLaunchPreflight{
		Order: 1, Phase: "runtime", APIVersion: "v1", Kind: "ServiceAccount",
		Namespace: runtime.receipt.Namespace, Name: runtime.receipt.Name, Method: "GET",
		ObjectPath: runtimeCollection + "/" + runtime.receipt.Name, ResponseMode: "FULL_OBJECT",
		ExistingPolicy: "VERIFY_EXACT", ObjectDigest: runtime.receipt.ObjectDigest,
	})
	creates = append(creates, SubmissionStageLaunchCreate{
		Order: 1, Phase: "runtime", APIVersion: "v1", Kind: "ServiceAccount",
		Namespace: runtime.receipt.Namespace, Name: runtime.receipt.Name, Method: "POST",
		CollectionPath: runtimeCollection, CreatePolicy: "CREATE_IF_ABSENT_OR_VERIFY_EXISTING", ObjectDigest: runtime.receipt.ObjectDigest,
	})

	for index, object := range credentialObjects {
		preflights = append(preflights, SubmissionStageLaunchPreflight{
			Order: index + 2, Phase: "credentials", APIVersion: "v1", Kind: "Secret",
			Namespace: submissionStageInputNamespace, Name: object.name, Method: "GET", ObjectPath: object.objectPath,
			ResponseMode: "FULL_OBJECT", ExistingPolicy: "VERIFY_EXACT_GLOBAL_STATE", ObjectDigest: object.objectDigest,
		})
		creates = append(creates, SubmissionStageLaunchCreate{
			Order: index + 2, Phase: "credentials", APIVersion: "v1", Kind: "Secret",
			Namespace: submissionStageInputNamespace, Name: object.name, Method: "POST", CollectionPath: object.collectionPath,
			CreatePolicy: "CREATE_ONLY_AFTER_GLOBAL_ABSENCE", ObjectDigest: object.objectDigest,
		})
	}
	for index, object := range stage.Creates {
		preflights = append(preflights, SubmissionStageLaunchPreflight{
			Order: index + 4, Phase: "stage-package", APIVersion: object.APIVersion, Kind: object.Kind,
			Namespace: object.Namespace, Name: object.Name, Method: object.PreflightMethod, ObjectPath: object.ObjectPath,
			ResponseMode: "FULL_OBJECT", ExistingPolicy: "VERIFY_EXACT_GLOBAL_STATE", ObjectDigest: object.ObjectDigest,
		})
		creates = append(creates, SubmissionStageLaunchCreate{
			Order: index + 4, Phase: "stage-package", APIVersion: object.APIVersion, Kind: object.Kind,
			Namespace: object.Namespace, Name: object.Name, Method: object.CreateMethod, CollectionPath: object.CollectionPath,
			CreatePolicy: "CREATE_ONLY_AFTER_GLOBAL_ABSENCE", ObjectDigest: object.ObjectDigest,
		})
	}
	return SubmissionStageLaunchPlan{
		Format: SubmissionStageLaunchPlanFormat, State: "VERIFIED", StageID: stage.StageID,
		Authority: packaged.installationAuthority, StagePackageDigest: stage.PackageDigest,
		CredentialPackageDigest: credentialReceipt.PackageDigest, RuntimeManifestDigest: runtime.receipt.ManifestDigest,
		PreflightBarrier: "ALL_ABSENT_OR_RUNTIME_ONLY_OR_ALL_EXACT", Preflights: preflights, Creates: creates, MutationAllowed: false,
	}, nil
}
