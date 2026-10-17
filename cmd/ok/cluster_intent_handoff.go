package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/openkubes/ok-cluster/internal/runner"
)

// No executor/authorization resolver is opened by this handoff. The existing
// manifest verifier remains the only source of a successful local identity.
func finishClusterIntentRunnerHandoff(material clusterIntentMaterialized, plan clusterIntentPlanArtifacts, preparationDigest string, stdout io.Writer) error {
	draft, err := runner.BuildBareClusterManifest(material.RuntimeInputsPath, runner.BareClusterManifestConfig{
		Root: material.Output, Expected: plan.Expected, NetworkProfileDigest: plan.NetworkProfileDigest,
		EnablementObject: plan.EnablementObject, TargetAccessObjects: plan.TargetAccessObjects,
	})
	if err != nil {
		return fmt.Errorf("YAML runner handoff incomplete: %w; partial static output retained", err)
	}
	for _, name := range []string{"runtime", "receipts", "authorizations"} {
		if err := os.Mkdir(filepath.Join(material.Output, name), 0o700); err != nil {
			return errors.New("YAML runner handoff output must be new; partial output retained")
		}
	}
	manifestPath := filepath.Join(material.Output, "full-run-manifest.json")
	if err := writeStaticBindingFile(manifestPath, draft.Raw); err != nil {
		return err
	}
	verified, err := prepareFullRunExecutionManifest(manifestPath)
	if err != nil {
		return errors.New("YAML runner handoff incomplete: existing full-run verifier rejected manifest/credentials; partial output retained")
	}
	if !validFullRunManifestReceiptFormat(verified.Format) || verified.State != "VERIFIED" || verified.MutationAllowed ||
		verified.PlanDigest != plan.SemanticDigest || verified.CompletionMode != plan.Expected.CompletionMode ||
		verified.NetworkProfileDigest != plan.NetworkProfileDigest || verified.ProjectionManifestDigest != material.Binding.Projection.ManifestDigest ||
		verified.ProjectionAuthorityDigest != material.Binding.Projection.AuthorityMapDigest || !sha256DigestPattern.MatchString(verified.ManifestDigest) {
		return errors.New("YAML runner handoff did not verify the exact generated Bare-MVP plan")
	}
	receipt := struct {
		Format                      string                                 `json:"format"`
		State                       string                                 `json:"state"`
		ManifestPath                string                                 `json:"manifestPath"`
		ManifestDigest              string                                 `json:"manifestDigest"`
		PreparationReceiptDigest    string                                 `json:"preparationReceiptDigest"`
		RuntimeInputsDigest         string                                 `json:"runtimeInputsDigest"`
		IndependentEvidenceKeyID    string                                 `json:"independentEvidenceKeyId"`
		Manifest                    runner.FullRunExecutionManifestReceipt `json:"manifest"`
		RunnerReady                 bool                                   `json:"runnerReady"`
		APIContacted                bool                                   `json:"apiContacted"`
		AuthorizationConsumed       bool                                   `json:"authorizationConsumed"`
		MutationAllowed             bool                                   `json:"mutationAllowed"`
		AuthorityDeploymentVerified bool                                   `json:"authorityDeploymentVerified"`
		LiveAuthorized              bool                                   `json:"liveAuthorized"`
		NextCommands                clusterIntentNextCommands              `json:"nextCommands"`
		NextAction                  string                                 `json:"nextAction"`
	}{Format: "ok-cli-cluster-runner-handoff/v1", State: "PREPARED_NOT_AUTHORIZED", ManifestPath: manifestPath, ManifestDigest: verified.ManifestDigest,
		PreparationReceiptDigest: preparationDigest, RuntimeInputsDigest: draft.RuntimeInputsDigest, IndependentEvidenceKeyID: draft.IndependentEvidenceKeyID, Manifest: verified, RunnerReady: true,
		NextCommands: preparedClusterIntentCommands(manifestPath, verified.ManifestDigest, draft.IndependentEvidencePublicKeyPath),
		NextAction:   "review generated plan and authority deployment separately; obtain explicit live approval for the technical JSON manifest digest; use the same independently reviewed evidence key; YAML --live requires this existing --prepared-dir and all original live gates"}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeStaticBindingFile(filepath.Join(material.Output, "runner-handoff-receipt.json"), raw); err != nil {
		return err
	}
	_, err = stdout.Write(raw)
	return err
}

// Argument arrays are review hints, never executed or interpreted by a shell.
// Neither their presence nor the preparation receipt authorizes live execution.
type clusterIntentNextCommands struct {
	DryRun            []string `json:"dryRun"`
	LiveAfterApproval []string `json:"liveAfterApproval"`
}

func preparedClusterIntentCommands(manifestPath, manifestDigest, evidenceKeyPath string) clusterIntentNextCommands {
	return clusterIntentNextCommands{
		DryRun: []string{"ok", "up", "--file", manifestPath, "--dry-run"},
		LiveAfterApproval: []string{"ok", "up", "--file", manifestPath, "--live", "--execute",
			"--expected-manifest-digest", manifestDigest, "--independent-evidence-public-key", evidenceKeyPath,
			"--terminal-marker", filepath.Join(filepath.Dir(manifestPath), "executor-terminal")},
	}
}
