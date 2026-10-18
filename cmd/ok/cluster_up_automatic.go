package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/stageauthority"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const automaticRequestFormat = "ok-cli-platform-preparation-request/v1"

// Non-authorizing request metadata. Policy derivation does not sign a grant,
// deploy RBAC or assert that a platform has accepted the request.
type automaticPreparationRequest struct {
	Format                     string                     `json:"format"`
	State                      string                     `json:"state"`
	IntentDigest               string                     `json:"normalizedIntentDigest"`
	BinaryDigest               string                     `json:"binaryDigest"`
	PreparationDigest          string                     `json:"preparationReceiptDigest"`
	StageAuthorityPolicyDigest string                     `json:"stageAuthorityPolicyDigest"`
	Plan                       clusterIntentPlanArtifacts `json:"plan"`
	Files                      map[string]string          `json:"files"`
	APIContacted               bool                       `json:"apiContacted"`
	MutationAllowed            bool                       `json:"mutationAllowed"`
	AuthorizationConsumed      bool                       `json:"authorizationConsumed"`
	RunnerReady                bool                       `json:"runnerReady"`
}

// Installed out of band by the platform operator, not inferred from admin
// kubeconfigs. This is an exact local handoff, not a grant or deployment proof.
type automaticPlatformHandoff struct {
	Format              string `json:"format"`
	RequestDigest       string `json:"requestDigest"`
	RuntimeInputsPath   string `json:"runtimeInputsPath"`
	RuntimeInputsDigest string `json:"runtimeInputsDigest"`
}

func runAutomaticClusterUp(ctx context.Context, path string, stdout, stderr io.Writer, runtime guidedUpRuntime, prepareOnly bool) error {
	if !prepareOnly && (!runtime.terminal || runtime.input == nil) {
		return errors.New("guided ok up requires a terminal; use --dry-run or --prepare without live confirmation")
	}
	intent, err := readClusterIntent(path)
	if err != nil {
		return err
	}
	intentRaw, _ := json.Marshal(intent)
	intentDigest := digest.SHA256(intentRaw)
	stateBase, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(stateBase) {
		return errors.New("automatic preparation requires an absolute user configuration directory")
	}
	root := filepath.Join(stateBase, "ok", "runs", intent.Metadata.Name)
	for _, dir := range []string{filepath.Join(stateBase, "ok"), filepath.Join(stateBase, "ok", "runs")} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			break
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("managed preparation parents must be private and non-symlink")
		}
	}
	if info, err := os.Lstat(root); os.IsNotExist(err) {
		if _, err := readClusterIntentTargets(path, intent); err != nil {
			return err
		}
		configPath, err := localConfigPath("")
		if err != nil {
			return err
		}
		sources, err := loadLocalConfig(configPath)
		if err != nil {
			return errors.New("automatic preparation needs trusted source paths; run ok config init (no credential paths are imported)")
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		binaryDigest, err := localCLIExecutableDigest(executable)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
			return err
		}
		// Recheck every newly created ancestor; never chmod existing user data.
		for _, dir := range []string{filepath.Dir(root), filepath.Dir(filepath.Dir(root))} {
			info, err := os.Lstat(dir)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return errors.New("managed preparation parents changed or are not private")
			}
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return errors.New("preparation already claimed; no automatic retry")
		}
		if prepareOnly {
			fmt.Fprintln(stderr, "Preparing Contract, seven-stage plan and bounded authority request locally. No API contact, credential renewal or grant issuance.")
		} else {
			fmt.Fprintln(stderr, "Preparing cluster locally. No cluster contact or credential changes.")
		}
		err = runClusterIntentMaterialize(ctx, []string{"--file", path, "--output", filepath.Join(root, "preparation"),
			"--lifecycle-root", sources.LifecycleRoot, "--ok-linux-path", sources.OKLinuxPath}, io.Discard, stderr, true,
			func(material clusterIntentMaterialized) error {
				return finishClusterIntentPrepareStatic(material, binaryDigest, io.Discard,
					func(material clusterIntentMaterialized, plan clusterIntentPlanArtifacts, preparation []byte) error {
						verified, err := stageplan.Load(filepath.Join(material.Output, "staged-plan.json"), plan.Expected)
						if err != nil {
							return err
						}
						policy, receipt, err := stageauthority.FromPlan(verified)
						if err != nil || receipt.MutationAllowed || receipt.ExecutionAttempt != "" {
							return errors.New("derive fresh bounded authority policy request")
						}
						if err := writeStaticBindingFile(filepath.Join(material.Output, "stage-authority-policy.json"), policy); err != nil {
							return err
						}
						files := map[string]string{}
						if err := filepath.WalkDir(material.Output, func(name string, entry fs.DirEntry, err error) error {
							if err != nil {
								return err
							}
							if entry.IsDir() {
								return nil
							}
							raw, err := readPrivatePreparationFile(name)
							if err != nil {
								return err
							}
							relative, err := filepath.Rel(material.Output, name)
							if err != nil {
								return err
							}
							files[filepath.ToSlash(relative)] = digest.SHA256(raw)
							return nil
						}); err != nil {
							return err
						}
						request := automaticPreparationRequest{Format: automaticRequestFormat, State: "AWAITING_PLATFORM_AUTHORITY",
							IntentDigest: intentDigest, BinaryDigest: binaryDigest, PreparationDigest: digest.SHA256(preparation),
							StageAuthorityPolicyDigest: receipt.PolicyDigest, Plan: plan, Files: files}
						raw, err := json.MarshalIndent(request, "", "  ")
						if err != nil {
							return err
						}
						return writeStaticBindingFile(filepath.Join(root, "platform-preparation-request.json"), raw)
					})
			})
		if err != nil {
			return fmt.Errorf("local preparation incomplete; evidence retained at %q; no automatic rerender: %w", root, err)
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("managed preparation root must be a private non-symlink directory")
	}
	if err := guidedUpNotStarted(root); err != nil {
		return err
	}
	if _, err := readClusterIntentTargets(path, intent); err != nil {
		return err
	}
	managed := false
	// Existing verified legacy handoffs keep the same final live boundary.
	if _, err := os.Lstat(filepath.Join(root, "managed-preparation.json")); err == nil {
		managed = true
		if _, err := os.Lstat(filepath.Join(root, "platform-preparation-request.json")); os.IsNotExist(err) {
			return completeAutomaticUp(ctx, path, root, stdout, stderr, runtime, prepareOnly)
		} else if err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := readPrivatePreparationFile(filepath.Join(root, "platform-preparation-request.json"))
	if err != nil {
		return errors.New("incomplete preparation retained; no automatic rerender, overwrite or retry")
	}
	var request automaticPreparationRequest
	if jsonstrict.Decode(raw, &request) != nil || request.Format != automaticRequestFormat || request.State != "AWAITING_PLATFORM_AUTHORITY" || request.IntentDigest != intentDigest || request.APIContacted || request.MutationAllowed || request.AuthorizationConsumed || request.RunnerReady {
		return errors.New("automatic preparation metadata or YAML changed; STOP without rerender")
	}
	requestDigest := digest.SHA256(raw)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	currentBinary, err := localCLIExecutableDigest(executable)
	if err != nil || currentBinary != request.BinaryDigest {
		return errors.New("CLI binary changed since preparation; no automatic rebind")
	}
	preparation := filepath.Join(root, "preparation")
	if len(request.Files) == 0 {
		return errors.New("empty static preparation inventory")
	}
	for name, expected := range request.Files {
		if !fs.ValidPath(name) || !sha256DigestPattern.MatchString(expected) {
			return errors.New("invalid static preparation inventory path/digest")
		}
		contents, err := readPrivatePreparationFile(filepath.Join(preparation, filepath.FromSlash(name)))
		if err != nil || digest.SHA256(contents) != expected {
			return errors.New("static preparation changed; STOP without rerender")
		}
	}
	if request.Files["preparation-receipt.json"] != request.PreparationDigest || request.Files["stage-authority-policy.json"] != request.StageAuthorityPolicyDigest {
		return errors.New("preparation request is not bound to its receipts/policy")
	}
	plan, err := stageplan.Load(filepath.Join(preparation, "staged-plan.json"), request.Plan.Expected)
	if err != nil || len(plan.Stages) != 7 || plan.ExecutionAttempt != "" || plan.PlanDigest != request.Plan.SemanticDigest {
		return errors.New("automatic request no longer binds the exact fresh plan")
	}
	policy, policyReceipt, err := stageauthority.FromPlan(plan)
	if err != nil || policyReceipt.PolicyDigest != request.StageAuthorityPolicyDigest || digest.SHA256(policy) != request.StageAuthorityPolicyDigest {
		return errors.New("bounded authority policy differs from verified plan")
	}
	if managed {
		return completeAutomaticUp(ctx, path, root, stdout, stderr, runtime, prepareOnly)
	}
	if _, err := os.Lstat(filepath.Join(root, "handoff-started.json")); err == nil {
		return errors.New("platform handoff already attempted; incomplete evidence retained; no automatic retry")
	} else if !os.IsNotExist(err) {
		return err
	}
	handoffPath := filepath.Join(root, "platform-handoff.json")
	if _, err := os.Lstat(handoffPath); os.IsNotExist(err) {
		if !prepareOnly {
			if err := writeAwaitingPlatformAccess(stdout, intent.Metadata.Name); err != nil {
				return err
			}
			return errors.New("cluster not started: platform access setup is incomplete; local preparation retained")
		}
		summary := map[string]any{"format": "ok-cli-automatic-preparation/v1", "state": "AWAITING_PLATFORM_AUTHORITY", "name": intent.Metadata.Name,
			"requestPath": filepath.Join(root, "platform-preparation-request.json"), "requestDigest": requestDigest, "stageAuthorityPolicyDigest": request.StageAuthorityPolicyDigest,
			"apiContacted": false, "mutationAllowed": false, "authorizationConsumed": false, "runnerReady": false,
			"nextAction": "Platform operator must separately review/install this exact bounded policy and provide a request-bound platform-handoff.json with existing private runtime references. No platform issuer is configured; no Contract/runtime path prompts or self-granted rights."}
		if err := json.NewEncoder(stdout).Encode(summary); err != nil {
			return err
		}
		return errors.New("local preparation complete; waiting for separately provided platform authority (NO-GO); no cluster started")
	} else if err != nil {
		return err
	}
	handoffRaw, err := readPrivatePreparationFile(handoffPath)
	if err != nil {
		return err
	}
	var handoff automaticPlatformHandoff
	if jsonstrict.Decode(handoffRaw, &handoff) != nil || handoff.Format != "ok-cli-platform-handoff/v1" || handoff.RequestDigest != requestDigest || !filepath.IsAbs(handoff.RuntimeInputsPath) || !sha256DigestPattern.MatchString(handoff.RuntimeInputsDigest) {
		return errors.New("platform handoff must bind the exact preparation request and existing private runtime references")
	}
	refs, err := readPrivatePreparationFile(handoff.RuntimeInputsPath)
	if err != nil || digest.SHA256(refs) != handoff.RuntimeInputsDigest {
		return errors.New("platform runtime references changed or are not private")
	}
	bindingRaw, err := readPrivatePreparationFile(filepath.Join(preparation, "binding-receipt.json"))
	if err != nil {
		return err
	}
	var binding clusterIntentBindingReceipt
	if jsonstrict.Decode(bindingRaw, &binding) != nil || binding.NormalizedIntentDigest != intentDigest {
		return errors.New("static binding differs from requested YAML")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeStaticBindingFile(filepath.Join(root, "handoff-started.json"), []byte(`{"format":"ok-cli-platform-handoff-start/v1"}`)); err != nil {
		return errors.New("platform handoff already claimed; no retry")
	}
	var output bytes.Buffer
	if err := finishClusterIntentRunnerHandoff(clusterIntentMaterialized{Output: preparation, IntentPath: path, RuntimeInputsPath: handoff.RuntimeInputsPath, Binding: binding}, request.Plan, request.PreparationDigest, &output); err != nil {
		return fmt.Errorf("platform handoff incomplete; retained without automatic retry: %w", err)
	}
	var receipt struct {
		ManifestDigest string `json:"manifestDigest"`
		EvidenceKeyID  string `json:"independentEvidenceKeyId"`
	}
	if json.Unmarshal(output.Bytes(), &receipt) != nil || !sha256DigestPattern.MatchString(receipt.ManifestDigest) || !sha256DigestPattern.MatchString(receipt.EvidenceKeyID) {
		return errors.New("invalid verified runner handoff")
	}
	setup := guidedUpPreparation{"ok-cli-managed-preparation/v1", intentDigest, receipt.ManifestDigest, handoff.RuntimeInputsPath, handoff.RuntimeInputsDigest, receipt.EvidenceKeyID}
	setupRaw, _ := json.MarshalIndent(setup, "", "  ")
	if err := writeStaticBindingFile(filepath.Join(root, "managed-preparation.json"), setupRaw); err != nil {
		return err
	}
	return completeAutomaticUp(ctx, path, root, stdout, stderr, runtime, prepareOnly)
}

// Presentation only: never turn retained local artifacts into execution
// readiness, prompt for approval, issue access, or consume a stage grant.
func writeAwaitingPlatformAccess(output io.Writer, name string) error {
	_, err := fmt.Fprintf(output, "Cluster %q\n  Local preparation: complete\n  Cluster creation:  not started\n\nPlatform access has not been provided for this run.\nA platform operator must finish the bounded access setup, including a reviewed\nworkload credential profile. Local preparation alone cannot authorize a run.\n\nNo cluster API was contacted. No credentials were issued or renewed.\nYour preparation is saved. Re-running does not grant access or start a cluster.\n", name)
	return err
}

func completeAutomaticUp(ctx context.Context, path, root string, stdout, stderr io.Writer, runtime guidedUpRuntime, prepareOnly bool) error {
	if !prepareOnly {
		return runGuidedClusterUpWithRuntime(ctx, path, stdout, stderr, runtime)
	}
	// Preparation-only never prompts or opens the live executor, including after
	// an independently supplied platform handoff. Reuse the full owner verifier.
	raw, err := readPrivatePreparationFile(filepath.Join(root, "managed-preparation.json"))
	if err != nil {
		return err
	}
	var setup guidedUpPreparation
	if jsonstrict.Decode(raw, &setup) != nil || setup.Format != "ok-cli-managed-preparation/v1" || !sha256DigestPattern.MatchString(setup.ManifestDigest) {
		return errors.New("invalid managed preparation")
	}
	prepared, err := resolvePreparedClusterIntent(path, filepath.Join(root, "preparation"), setup.ManifestDigest)
	if err != nil {
		return fmt.Errorf("managed preparation verification failed: %w", err)
	}
	if prepared.Binding.NormalizedIntentDigest != setup.IntentDigest {
		return errors.New("managed preparation differs from verified YAML/manifest")
	}
	if _, err := guidedUpEvidencePath(setup); err != nil {
		return err
	}
	receipt, err := readPrivatePreparationFile(filepath.Join(root, "preparation", "runner-handoff-receipt.json"))
	if err != nil {
		return err
	}
	var handoff struct {
		Format                      string `json:"format"`
		State                       string `json:"state"`
		ManifestDigest              string `json:"manifestDigest"`
		RuntimeDigest               string `json:"runtimeInputsDigest"`
		KeyID                       string `json:"independentEvidenceKeyId"`
		RunnerReady                 bool   `json:"runnerReady"`
		APIContacted                bool   `json:"apiContacted"`
		MutationAllowed             bool   `json:"mutationAllowed"`
		AuthorizationConsumed       bool   `json:"authorizationConsumed"`
		LiveAuthorized              bool   `json:"liveAuthorized"`
		AuthorityDeploymentVerified bool   `json:"authorityDeploymentVerified"`
	}
	if json.Unmarshal(receipt, &handoff) != nil || handoff.Format != "ok-cli-cluster-runner-handoff/v1" || handoff.State != "PREPARED_NOT_AUTHORIZED" || handoff.ManifestDigest != setup.ManifestDigest || handoff.RuntimeDigest != setup.RuntimeInputsDigest || handoff.KeyID != setup.EvidenceKeyID || !handoff.RunnerReady || handoff.APIContacted || handoff.MutationAllowed || handoff.AuthorizationConsumed || handoff.LiveAuthorized || handoff.AuthorityDeploymentVerified {
		return errors.New("runner handoff receipt differs from verified preparation")
	}
	_, err = stdout.Write(receipt)
	return err
}
