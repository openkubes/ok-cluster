package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingStageLaunchReceiptFormat = "ok147-runtime-binding-stage-launch-receipt/v1"

type RuntimeBindingStageLaunchReceipt struct {
	Format                  string                        `json:"format"`
	StageID                 string                        `json:"stageId"`
	StagePackageDigest      string                        `json:"stagePackageDigest"`
	CredentialPackageDigest string                        `json:"credentialPackageDigest"`
	RuntimeManifestDigest   string                        `json:"runtimeManifestDigest"`
	Authority               string                        `json:"authority"`
	State                   string                        `json:"state"`
	MutationState           string                        `json:"mutationState"`
	Results                 []SubmissionStageLaunchResult `json:"results"`
}

// Launch is a single-use, seven-object create-only operation. It completes all
// exact GETs before its first POST and has no retry, update, patch, apply,
// delete, list or watch path.
func (opened *OpenedRuntimeBindingStageLaunch) Launch(ctx context.Context) (RuntimeBindingStageLaunchReceipt, error) {
	receipt := opened.newLaunchReceipt()
	if opened == nil || opened.client == nil || opened.clock == nil || opened.endpoint == nil {
		return receipt, errors.New("opened runtime binding launch is required")
	}
	opened.mu.Lock()
	if opened.used {
		opened.mu.Unlock()
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("runtime binding launcher is single-use"))
	}
	opened.used = true
	opened.mu.Unlock()
	if _, err := opened.Receipt(); err != nil {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
	}

	plan, err := PlanRuntimeBindingStageLaunch(opened.material.packaged, opened.material.credentials, opened.material.runtime)
	if err != nil {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
	}
	_, objects, err := prepareRuntimeBindingStageInstallation(opened.material.packaged)
	if err != nil {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
	}
	credentials, secrets, err := prepareRuntimeBindingStageCredentialInstallation(opened.material.credentials)
	if err != nil {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
	}
	now := opened.clock().UTC()
	if now.After(opened.validUntil) {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("runtime binding launch candidate validity has expired"))
	}
	for _, secret := range secrets {
		if secret.expiresAt.Sub(now) < minimumStageCredentialRemaining {
			return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("runtime binding credential has insufficient remaining lifetime"))
		}
	}
	if credentials.PackageDigest != opened.material.receipt.CredentialPackageDigest {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("runtime binding credential package changed before launch"))
	}

	existing := make(map[int]SubmissionStageLaunchResult, len(plan.Preflights))
	for _, preflight := range plan.Preflights {
		raw, status, err := opened.launchRequest(ctx, http.MethodGet, preflight.ObjectPath, nil)
		if err != nil {
			return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
		}
		switch status {
		case http.StatusNotFound:
		case http.StatusOK:
			result, err := verifyExistingRuntimeBindingLaunchObject(preflight, raw, opened.material.runtime, objects, secrets)
			if err != nil {
				return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", err)
			}
			existing[preflight.Order] = result
		default:
			return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", submissionStageLaunchStatusError(http.MethodGet, status))
		}
	}
	if len(existing) == len(plan.Preflights) {
		receipt.State = "ALREADY_LAUNCHED"
		for order := 1; order <= len(plan.Preflights); order++ {
			receipt.Results = append(receipt.Results, existing[order])
		}
		return receipt, nil
	}
	runtimeResult, runtimeExists := existing[1]
	if len(existing) != 0 && !(len(existing) == 1 && runtimeExists) {
		return stopRuntimeBindingStageLaunch(receipt, "STOPPED_ZERO_WRITE", errors.New("runtime binding launch found exact partial state"))
	}

	receipt.State = "LAUNCHING"
	if runtimeExists {
		receipt.Results = append(receipt.Results, runtimeResult)
	} else {
		result, err := opened.createRuntimeBindingLaunchObject(ctx, plan.Creates[0], opened.material.runtime.raw, "runtime")
		if err != nil {
			return stopRuntimeBindingAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index := 0; index < 2; index++ {
		result, err := opened.createRuntimeBindingLaunchObject(ctx, plan.Creates[index+1], objects[index].raw, "stage-prerequisites")
		if err != nil {
			return stopRuntimeBindingAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	for index, secret := range secrets {
		result, err := opened.createRuntimeBindingLaunchObject(ctx, plan.Creates[index+3], secret.raw, "credentials")
		if err != nil {
			return stopRuntimeBindingAfterAttempt(receipt, err)
		}
		receipt.MutationState = "ATTEMPTED"
		receipt.Results = append(receipt.Results, result)
	}
	result, err := opened.createRuntimeBindingLaunchObject(ctx, plan.Creates[6], objects[2].raw, "job")
	if err != nil {
		return stopRuntimeBindingAfterAttempt(receipt, err)
	}
	receipt.MutationState = "ATTEMPTED"
	receipt.Results = append(receipt.Results, result)
	receipt.State = "LAUNCHED"
	return receipt, nil
}

func verifyExistingRuntimeBindingLaunchObject(preflight SubmissionStageLaunchPreflight, raw []byte, runtime VerifiedRuntimeBindingStageRuntimePrerequisite, objects []submissionStageInstallObject, secrets []submissionStageCredentialInstallObject) (SubmissionStageLaunchResult, error) {
	var uid, resourceVersion string
	var err error
	switch preflight.Phase {
	case "runtime":
		uid, resourceVersion, err = verifySubmissionStageRuntimeObject(raw, runtime.raw)
	case "stage-prerequisites":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, objects[preflight.Order-2])
	case "credentials":
		uid, resourceVersion, err = verifySubmissionStageCredentialCreatedObject(raw, secrets[preflight.Order-4])
	case "job":
		uid, resourceVersion, err = verifySubmissionStageCreatedObject(raw, objects[2])
	default:
		return SubmissionStageLaunchResult{}, errors.New("runtime binding preflight phase is invalid")
	}
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("existing runtime binding object differs from verified plan")
	}
	return runtimeBindingLaunchResult(preflight, "EXISTING_VERIFIED", uid, resourceVersion), nil
}

func (opened *OpenedRuntimeBindingStageLaunch) createRuntimeBindingLaunchObject(ctx context.Context, create SubmissionStageLaunchCreate, body []byte, phase string) (SubmissionStageLaunchResult, error) {
	raw, status, err := opened.launchRequest(ctx, http.MethodPost, create.CollectionPath, body)
	if err != nil || status != http.StatusCreated {
		return SubmissionStageLaunchResult{}, submissionStageLaunchCreateError(status, err)
	}
	var uid, resourceVersion string
	if phase == "runtime" {
		uid, resourceVersion, err = verifySubmissionStageRuntimeObject(raw, body)
	} else {
		uid, resourceVersion, err = verifyCreatedRuntimeBindingBody(raw, body)
	}
	if err != nil {
		return SubmissionStageLaunchResult{}, errors.New("created runtime binding object differs")
	}
	preflight := SubmissionStageLaunchPreflight{Order: create.Order, Phase: phase, APIVersion: create.APIVersion, Kind: create.Kind, Namespace: create.Namespace, Name: create.Name, ObjectDigest: create.ObjectDigest}
	return runtimeBindingLaunchResult(preflight, "CREATED", uid, resourceVersion), nil
}

func verifyCreatedRuntimeBindingBody(response, expected []byte) (string, string, error) {
	object := submissionStageInstallObject{raw: expected}
	return verifySubmissionStageCreatedObject(response, object)
}

func (opened *OpenedRuntimeBindingStageLaunch) launchRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	endpoint := *opened.endpoint
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("construct bounded runtime binding launch request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+opened.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := opened.client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("bounded runtime binding launch %s failed", method)
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumStageInstallationResponseBytes+1))
	if readErr != nil || len(raw) > maximumStageInstallationResponseBytes {
		return nil, 0, errors.New("bounded runtime binding response exceeds accepted size")
	}
	if len(raw) > 0 {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, 0, errors.New("bounded runtime binding response is not JSON")
		}
	}
	return raw, response.StatusCode, nil
}

func (opened *OpenedRuntimeBindingStageLaunch) newLaunchReceipt() RuntimeBindingStageLaunchReceipt {
	receipt := RuntimeBindingStageLaunchReceipt{Format: RuntimeBindingStageLaunchReceiptFormat, State: "PREFLIGHT", MutationState: "NOT_ATTEMPTED", Results: []SubmissionStageLaunchResult{}}
	if opened != nil {
		receipt.StageID = opened.material.receipt.StageID
		receipt.Authority = opened.material.receipt.Authority
		receipt.StagePackageDigest = opened.material.receipt.StagePackageDigest
		receipt.CredentialPackageDigest = opened.material.receipt.CredentialPackageDigest
		receipt.RuntimeManifestDigest = opened.material.receipt.RuntimeManifestDigest
	}
	return receipt
}

func runtimeBindingLaunchResult(preflight SubmissionStageLaunchPreflight, state, uid, resourceVersion string) SubmissionStageLaunchResult {
	return SubmissionStageLaunchResult{
		Order: preflight.Order, Phase: preflight.Phase, APIVersion: preflight.APIVersion, Kind: preflight.Kind,
		Namespace: preflight.Namespace, Name: preflight.Name, ObjectDigest: preflight.ObjectDigest, ObjectState: state,
		UIDDigest: digest.SHA256([]byte(uid)), ResourceVersionDigest: digest.SHA256([]byte(resourceVersion)),
	}
}

func stopRuntimeBindingAfterAttempt(receipt RuntimeBindingStageLaunchReceipt, err error) (RuntimeBindingStageLaunchReceipt, error) {
	receipt.MutationState = "ATTEMPTED_UNKNOWN"
	return stopRuntimeBindingStageLaunch(receipt, "STOPPED_PARTIAL_OR_UNKNOWN", err)
}

func stopRuntimeBindingStageLaunch(receipt RuntimeBindingStageLaunchReceipt, state string, err error) (RuntimeBindingStageLaunchReceipt, error) {
	receipt.State = state
	return receipt, err
}
