package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/submission"
)

func bareClusterCreateManifestReceipt() runner.FullRunExecutionManifestReceipt {
	return runner.FullRunExecutionManifestReceipt{
		Format: runner.FullRunExecutionManifestReceiptFormatV2, State: "VERIFIED",
		ManifestDigest: testSHA("1"), PlanDigest: testSHA("2"),
		CompletionMode: stageplan.CompletionModeBareClusterMVP,
	}
}

func TestHierarchicalHelp(t *testing.T) {
	for name, test := range map[string]struct {
		arguments []string
		contains  []string
	}{
		"root":                   {[]string{"--help"}, []string{"ok <command>", "cluster"}},
		"cluster":                {[]string{"cluster", "--help"}, []string{"ok cluster <command>", "create"}},
		"authority":              {[]string{"authority", "--help"}, []string{"ok authority stage", "bounded stage authority"}},
		"authority stage":        {[]string{"authority", "stage", "--help"}, []string{"launch execute", "separate approval"}},
		"evidence":               {[]string{"evidence", "--help"}, []string{"ok evidence observability", "independent evidence"}},
		"evidence observability": {[]string{"evidence", "observability", "--help"}, []string{"observability serve", "configured listener"}},
		"cluster create":         {[]string{"cluster", "create", "--help"}, []string{"--file", "--dry-run", "--prepare", "--live --execute", "may create cluster resources", "lifecycle operator owns", "does not renew provider credentials"}},
		"create requirements":    {[]string{"cluster", "create", "requirements", "--help"}, []string{"machine-readable", "reads no file", "does not prepare"}},
		"create template":        {[]string{"cluster", "create", "manifest-template", "--help"}, []string{"manifest skeleton", "invalid placeholder", "authoritative renderer"}},
		"create plan template":   {[]string{"cluster", "create", "plan-template", "--help"}, []string{"seven-stage", "NO-GO", "authoritative renderer"}},
		"create scaffold":        {[]string{"cluster", "create", "scaffold", "--help"}, []string{"must not exist", "contacts no API", "invalid"}},
		"create trailing help":   {[]string{"cluster", "create", "--file", "/private/run.json", "--help"}, []string{"--file", "--dry-run", "--live --execute"}},
		"cluster dry-run":        {[]string{"cluster", "dry-run", "--help"}, []string{"dry-run serve", "legacy HTTP validation"}},
		"cluster stage":          {[]string{"cluster", "stage", "--help"}, []string{"Expert stage-level", "observe", "launch"}},
		"cluster stage run":      {[]string{"cluster", "stage", "run", "--help"}, []string{"Manual Bare-MVP order", "provider-prerequisites", "separate approval"}},
		"stage run full":         {[]string{"cluster", "stage", "run", "full", "--help"}, []string{"in-process executor", "four-object installation plan", "different live boundaries"}},
		"stage observe":          {[]string{"cluster", "stage", "observe", "--help"}, []string{"lifecycle", "network", "do not repair"}},
		"stage bind":             {[]string{"cluster", "stage", "bind", "--help"}, []string{"runtime identity", "Bare-MVP Stage 6", "--execute"}},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(test.arguments, &stdout, &stderr); err != nil {
				t.Fatalf("help failed: %v", err)
			}
			for _, expected := range test.contains {
				if !strings.Contains(stdout.String(), expected) {
					t.Fatalf("help missing %q:\n%s", expected, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("unexpected stderr: %s", stderr.String())
			}
		})
	}
}

func TestClusterCreatePlanTemplateBindsExactSevenStageSequence(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "create", "plan-template"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	stages, ok := plan["stages"].([]any)
	if !ok || len(stages) != 7 || plan["authorizationState"] != "NO-GO" ||
		plan["completionMode"] != stageplan.CompletionModeBareClusterMVP {
		t.Fatalf("unexpected Bare-MVP plan template: %#v", plan)
	}
	last := stages[6].(map[string]any)
	if last["id"] != "target-access" || last["grantOperation"] != "CreateTargetAccess" {
		t.Fatalf("unexpected terminal Bare-MVP stage: %#v", last)
	}

	identity := contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"}
	plan["contractIdentity"] = map[string]any{"namespace": identity.Namespace, "name": identity.Name}
	for _, field := range []string{"intentRevision", "enablementRevision", "platformRevision", "executionFixture"} {
		plan[field] = testSHA("1")
	}
	if _, exists := plan["executionAttemptDigest"]; exists || plan["format"] != stageplan.Format {
		t.Fatalf("first-run plan template bound recovery identity: %#v", plan)
	}
	for _, item := range stages {
		for _, input := range item.(map[string]any)["inputs"].([]any) {
			input.(map[string]any)["digest"] = testSHA("1")
		}
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := stageplan.Verify(raw, stageplan.Expected{
		ContractIdentity: identity, IntentRevision: testSHA("1"), EnablementRevision: testSHA("1"),
		PlatformRevision: testSHA("1"), ExecutionFixture: testSHA("1"),
		InfrastructureAuthority: "ok-infra", ManagementAuthority: "ok-mgmt", GitOpsAuthority: "ok-gitops",
		CompletionMode: stageplan.CompletionModeBareClusterMVP,
	})
	if err != nil || len(binding.Stages) != 7 {
		t.Fatalf("rendered plan template did not satisfy the production verifier: %#v err=%v", binding, err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	if err := run([]string{"cluster", "create", "plan-template", "extra"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("plan-template accepted positional input")
	}
}

func TestClusterCreateManifestTemplateIsMachineReadableAndNonAuthorizing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "create", "manifest-template"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	plan, ok := manifest["plan"].(map[string]any)
	if !ok {
		t.Fatalf("template plan is missing: %#v", manifest)
	}
	expected, ok := plan["expected"].(map[string]any)
	if !ok || expected["completionMode"] != stageplan.CompletionModeBareClusterMVP ||
		manifest["format"] != runner.FullRunExecutionManifestFormat {
		t.Fatalf("template plan boundary is invalid: %#v", plan)
	}
	if _, exists := expected["executionAttemptDigest"]; exists {
		t.Fatalf("first-run manifest template bound recovery identity: %#v", expected)
	}
	providerAccess, ok := manifest["providerAccess"].(map[string]any)
	if !ok || providerAccess["kubeconfigFile"] != "/private/replace/provider-access.kubeconfig" {
		t.Fatalf("template provider-access kubeconfig path is not explicit: %#v", providerAccess)
	}
	wantWorkload := map[string]any{
		"bindingPath":    "/private/replace/runtime/workload-authority.json",
		"kubeconfigFile": "/private/replace/runtime/workload.kubeconfig",
		"caFile":         "/private/replace/runtime/workload-ca.crt",
	}
	for _, section := range []string{"networkObservation", "runtimeBinding", "targetAccess"} {
		value, ok := manifest[section].(map[string]any)
		if !ok {
			t.Fatalf("template section %s is missing: %#v", section, manifest)
		}
		workload, ok := value["workload"].(map[string]any)
		if !ok || len(workload) != len(wantWorkload) {
			t.Fatalf("template section %s lacks the exact workload path binding: %#v", section, workload)
		}
		for field, want := range wantWorkload {
			if workload[field] != want {
				t.Fatalf("template section %s %s = %#v, want %q", section, field, workload[field], want)
			}
		}
	}
	for _, source := range []struct{ section, field string }{
		{"providerPrerequisites", "authority"},
		{"clusterLifecycle", "authority"},
		{"lifecycleObservation", "management"},
	} {
		section, ok := manifest[source.section].(map[string]any)
		authority, authorityOK := section[source.field].(map[string]any)
		if !ok || !authorityOK || authority["endpoint"] == "" || authority["tokenFile"] == "" ||
			authority["caFile"] == "" || authority["caBundleDigest"] == "" {
			t.Fatalf("template section %s lacks its explicit authority: %#v", source.section, section)
		}
		if _, exists := authority["kubeconfigFile"]; exists {
			t.Fatalf("management authority section %s silently selected a kubeconfig: %#v", source.section, authority)
		}
	}
	if strings.Contains(stdout.String(), "~/.kube") || strings.Contains(stdout.String(), "$HOME") {
		t.Fatalf("template contains an implicit home-directory kubeconfig path: %s", stdout.String())
	}
	targetAccess, ok := manifest["targetAccess"].(map[string]any)
	if !ok {
		t.Fatalf("template target access is missing: %#v", manifest)
	}
	objects, ok := targetAccess["expectedObjects"].([]any)
	if !ok || len(objects) != submission.TargetAccessObjectCount {
		t.Fatalf("template target access inventory is invalid: %#v", targetAccess)
	}
	for _, forbidden := range []string{"targetCredential", "targetRegistration", "platformApplications", "observabilityCollector"} {
		if _, exists := manifest[forbidden]; exists {
			t.Fatalf("template included unused post-runtime section %q", forbidden)
		}
	}
	if !strings.Contains(stdout.String(), "<replace-with-64-lowercase-hex>") || stderr.Len() != 0 {
		t.Fatalf("template did not retain fail-closed placeholders: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	templatePath := filepath.Join(t.TempDir(), "bare-run.template.json")
	if err := os.WriteFile(templatePath, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runner.LoadFullRunExecutionManifest(templatePath); err == nil {
		t.Fatal("unrendered manifest template passed the production loader")
	}
	if err := run([]string{"cluster", "create", "manifest-template", "extra"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("manifest-template accepted positional input")
	}
}

func TestClusterCreateScaffoldIsPrivateCreateOnlyAndNameBound(t *testing.T) {
	parent := t.TempDir()
	output := filepath.Join(parent, "runner-inputs")
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "create", "scaffold", "--name", "ok-cli-mvp", "--output", output}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var receipt clusterCreateScaffoldReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != "SCAFFOLDED" || receipt.ContractName != "ok-cli-mvp" || receipt.APIContacted || receipt.MutationAllowed || len(receipt.Files) != 2 || stderr.Len() != 0 {
		t.Fatalf("unexpected scaffold receipt: %#v stderr=%s", receipt, stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("scaffold directory is not private: mode=%v err=%v", info.Mode(), err)
	}
	for _, path := range receipt.Files {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("scaffold file is not private: path=%s mode=%v err=%v", path, info.Mode(), err)
		}
	}
	manifestRaw, err := os.ReadFile(filepath.Join(output, "full-run-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	expected := manifest["plan"].(map[string]any)["expected"].(map[string]any)
	identity := expected["contractIdentity"].(map[string]any)
	targetObjects := manifest["targetAccess"].(map[string]any)["expectedObjects"].([]any)
	clusterRole := targetObjects[submission.TargetAccessBaseObjectCount].(map[string]any)
	if identity["name"] != "ok-cli-mvp" || identity["namespace"] != "ok-cli-mvp" ||
		manifest["plan"].(map[string]any)["path"] != filepath.Join(output, "staged-plan.json") ||
		clusterRole["name"] != "ok-cli-mvp-observability-core-kube-state-metrics" {
		t.Fatalf("scaffold manifest is not name/path bound: %#v", manifest)
	}
	if err := run([]string{"cluster", "create", "scaffold", "--name", "ok-cli-mvp", "--output", output}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("scaffold reused its output: %v", err)
	}
	if err := run([]string{"cluster", "create", "scaffold", "--name", "Existing_Name", "--output", filepath.Join(parent, "other")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("scaffold accepted an invalid cluster name")
	}
}

func TestClusterCreateRequirementsAreMachineReadableAndNonMutating(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "create", "requirements"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var requirements clusterCreateRequirements
	if err := json.Unmarshal(stdout.Bytes(), &requirements); err != nil {
		t.Fatal(err)
	}
	if requirements.Format != clusterCreateRequirementsFormat || requirements.Operation != "CreateCluster" ||
		requirements.RequiredCompletionMode != stageplan.CompletionModeBareClusterMVP ||
		requirements.OfflineAPIContacted || requirements.OfflineMutationAllowed || !requirements.LiveMutationAllowed ||
		requirements.PostRuntimeMaterialRequired || len(requirements.RequiredManifestSections) != 14 ||
		len(requirements.UnusedPostRuntimeSections) != 9 ||
		len(requirements.AcceptedPlanStageCounts) != 2 || requirements.AcceptedPlanStageCounts[0] != 7 ||
		requirements.PreferredPlanStageCount != 7 ||
		requirements.TerminalMarkerName != runner.FullRunExecutorTerminalMarkerName ||
		len(requirements.AcceptedManifestFormats) != 2 || len(requirements.LiveStageOrder) != 7 ||
		requirements.LiveStageOrder[1] != "cluster-lifecycle" || stderr.Len() != 0 {
		t.Fatalf("unexpected create requirements: %#v stderr=%s", requirements, stderr.String())
	}
	if err := run([]string{"cluster", "create", "requirements", "extra"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("requirements command accepted positional input")
	}
}

func TestClusterCreateProviderOwnershipIsDescriptiveAndDoesNotChangeManifest(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"cluster", "create", "requirements"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var requirements clusterCreateRequirements
	if err := json.Unmarshal(stdout.Bytes(), &requirements); err != nil {
		t.Fatal(err)
	}
	ownership := requirements.ProviderAccessOwnership
	if ownership.LifecycleOwner != "lifecycle-operator" || !ownership.RequiredAfterExecution || ownership.AutomaticRenewalByCLI || ownership.OfflineValidationProvesOngoingAccess || len(ownership.OperatorHandoff) != 3 {
		t.Fatalf("provider lifecycle responsibility differs: %#v", ownership)
	}
	if stderr.Len() != 0 || requirements.Format != clusterCreateRequirementsFormat {
		t.Fatal("requirements routing or format changed")
	}
	for _, section := range requirements.RequiredManifestSections {
		if strings.Contains(strings.ToLower(section), "ownership") || strings.Contains(strings.ToLower(section), "rotation") {
			t.Fatal("descriptive ownership became a required manifest input")
		}
	}
	stdout.Reset()
	if err := run([]string{"cluster", "create", "manifest-template"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if _, exists := manifest["providerAccessOwnership"]; exists {
		t.Fatal("descriptive requirements metadata changed the manifest contract")
	}
	var providerAccess map[string]json.RawMessage
	if err := json.Unmarshal(manifest["providerAccess"], &providerAccess); err != nil {
		t.Fatal(err)
	}
	if len(providerAccess) != 2 || providerAccess["policyPath"] == nil || providerAccess["kubeconfigFile"] == nil {
		t.Fatal("provider credential input contract changed")
	}
}

func TestLeafFlagHelpIsSuccessfulAndUsesStdout(t *testing.T) {
	for name, arguments := range map[string][]string{
		"full prepare":      {"cluster", "stage", "run", "full", "prepare", "--help"},
		"observe lifecycle": {"cluster", "stage", "observe", "lifecycle", "--help"},
		"bind runtime":      {"cluster", "stage", "bind", "runtime", "--help"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(arguments, &stdout, &stderr); err != nil {
				t.Fatalf("leaf help failed: %v", err)
			}
			if !strings.Contains(stdout.String(), "Usage of ok cluster stage") {
				t.Fatalf("leaf help missing usage:\n%s", stdout.String())
			}
			if strings.Contains(stdout.String(), "ERROR:") || stderr.Len() != 0 {
				t.Fatalf("leaf help reported an error: stdout=%s stderr=%s", stdout.String(), stderr.String())
			}
		})
	}
}

func TestClusterCreateFileRejectsAmbiguousFileFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"cluster", "create", "--file", "/private/a.json", "-f", "/private/b.json", "--dry-run"},
		{"cluster", "create", "--file=/private/a.json", "--file=/private/b.json", "--prepare"},
	} {
		var stdout bytes.Buffer
		err := run(arguments, &stdout, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "exactly one --file") || stdout.Len() != 0 {
			t.Fatalf("ambiguous file input accepted: arguments=%v err=%v stdout=%s", arguments, err, stdout.String())
		}
	}
}

func TestClusterCreateRoutesIncompleteProductAndLegacyInputsClearly(t *testing.T) {
	for name, arguments := range map[string][]string{
		"dry-run without file": {"cluster", "create", "--dry-run"},
		"prepare without file": {"cluster", "create", "--prepare"},
		"live without file":    {"cluster", "create", "--live", "--execute"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(arguments, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), "exactly one --file or -f input is required") {
				t.Fatalf("incomplete product command reached the wrong parser: err=%v stderr=%s", err, stderr.String())
			}
		})
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{"cluster", "create", "--contract", "/missing/contract", "--schema", "/missing/schema", "--dry-run"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "read contract") {
		t.Fatalf("legacy command did not reach the legacy parser: err=%v stderr=%s", err, stderr.String())
	}

	err = run([]string{
		"cluster", "create", "--file", "/private/run.json", "--prepare",
		"--contract", "/legacy/contract", "--schema", "/legacy/schema",
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed product and legacy flags were not rejected clearly: err=%v", err)
	}
}

func TestClusterCreateFileDryRunAndPrepareAreNonMutating(t *testing.T) {
	previousPrepare := prepareFullRunExecutionManifest
	previousExecute := executeClusterCreateLive
	previousMarkerValidation := validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest = previousPrepare
		executeClusterCreateLive = previousExecute
		validateClusterCreateTerminalMarker = previousMarkerValidation
	}()
	liveCalls, markerCalls := 0, 0
	executeClusterCreateLive = func(context.Context, clusterCreateLiveConfig, io.Writer, io.Writer) error {
		liveCalls++
		return errors.New("offline mode reached live executor")
	}
	validateClusterCreateTerminalMarker = func(string) error {
		markerCalls++
		return errors.New("offline mode reached live marker preflight")
	}
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		if path != "/private/bare-run.json" {
			t.Fatalf("manifest path = %q", path)
		}
		return bareClusterCreateManifestReceipt(), nil
	}
	for _, mode := range []struct {
		flag, state, next string
	}{
		{"--dry-run", "VALIDATED", "review the validated identities, then run --prepare with the same file"},
		{"--prepare", "PREPARED", "obtain separate live approval; pass manifestDigest as --expected-manifest-digest"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run([]string{"cluster", "create", "--file", "/private/bare-run.json", mode.flag}, &stdout, &stderr); err != nil {
			t.Fatalf("%s: %v", mode.flag, err)
		}
		var receipt clusterCreateWorkflowReceipt
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Format != clusterCreateWorkflowFormat || receipt.State != mode.state || receipt.MutationAllowed ||
			receipt.APIContacted || receipt.AuthorizationConsumed || receipt.NextAction != mode.next ||
			receipt.CompletionMode != stageplan.CompletionModeBareClusterMVP || receipt.ManifestDigest != testSHA("1") {
			t.Fatalf("unsafe or incomplete receipt: %#v", receipt)
		}
		for _, forbidden := range []string{"/private/", "bare-run.json", "credential", "kubeconfig", "token"} {
			if strings.Contains(strings.ToLower(stdout.String()), forbidden) {
				t.Fatalf("offline receipt disclosed %q: %s", forbidden, stdout.String())
			}
		}
	}
	if liveCalls != 0 || markerCalls != 0 {
		t.Fatalf("offline modes reached live boundaries: executor=%d marker=%d", liveCalls, markerCalls)
	}
}

func TestClusterCreateFileRejectsNonBareManifest(t *testing.T) {
	previous := prepareFullRunExecutionManifest
	defer func() { prepareFullRunExecutionManifest = previous }()
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		receipt := bareClusterCreateManifestReceipt()
		receipt.CompletionMode = ""
		return receipt, nil
	}
	var stdout bytes.Buffer
	err := run([]string{"cluster", "create", "-f", "/private/full-run.json", "--prepare"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), stageplan.CompletionModeBareClusterMVP) || stdout.Len() != 0 {
		t.Fatalf("non-bare manifest accepted: err=%v stdout=%s", err, stdout.String())
	}
}

func TestClusterCreateLiveRequiresPreparedIdentityAndExplicitDoubleGate(t *testing.T) {
	previousPrepare := prepareFullRunExecutionManifest
	previousExecute := executeClusterCreateLive
	previousMarkerValidation := validateClusterCreateTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest = previousPrepare
		executeClusterCreateLive = previousExecute
		validateClusterCreateTerminalMarker = previousMarkerValidation
	}()
	validateClusterCreateTerminalMarker = func(path string) error {
		if path != "/private/executor-terminal" {
			t.Fatalf("terminal marker path = %q", path)
		}
		return nil
	}
	prepareFullRunExecutionManifest = func(string) (runner.FullRunExecutionManifestReceipt, error) {
		return bareClusterCreateManifestReceipt(), nil
	}
	calls := 0
	executeClusterCreateLive = func(ctx context.Context, config clusterCreateLiveConfig, stdout, stderr io.Writer) error {
		calls++
		if config.ManifestPath != "/private/bare-run.json" || config.ExpectedManifestDigest != testSHA("1") ||
			config.IndependentEvidencePublicKey != "/private/evidence.pub" || config.TerminalMarker != "/private/executor-terminal" {
			t.Fatalf("live config differs: %#v", config)
		}
		_, _ = stdout.Write([]byte("{\"state\":\"SUCCEEDED\"}\n"))
		return nil
	}
	valid := []string{
		"cluster", "create", "--file", "/private/bare-run.json", "--live", "--execute",
		"--expected-manifest-digest", testSHA("1"),
		"--independent-evidence-public-key", "/private/evidence.pub",
		"--terminal-marker", "/private/executor-terminal",
	}
	for name, arguments := range map[string][]string{
		"missing live":            removeArgument(valid, "--live"),
		"missing execute":         removeArgument(valid, "--execute"),
		"wrong prepared identity": replaceArgument(valid, "--expected-manifest-digest", testSHA("3")),
		"mixed modes":             append(append([]string(nil), valid...), "--prepare"),
	} {
		t.Run(name, func(t *testing.T) {
			before := calls
			if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe live invocation was accepted")
			}
			if calls != before {
				t.Fatalf("unsafe invocation reached live executor: calls=%d before=%d", calls, before)
			}
		})
	}
	var stdout bytes.Buffer
	if err := run(valid, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(stdout.String(), "SUCCEEDED") {
		t.Fatalf("live execution not forwarded exactly once: calls=%d stdout=%s", calls, stdout.String())
	}
}

func TestClusterCreateLiveDelegatesThroughFullRunnerBoundary(t *testing.T) {
	previousPrepare := prepareFullRunExecutionManifest
	previousBareOpen := openBareClusterFullRunActivation
	previousObservabilityOpen := openKubernetesObservabilityFullRunActivation
	previousWriter := writeFullRunExecutorTerminalMarker
	defer func() {
		prepareFullRunExecutionManifest = previousPrepare
		openBareClusterFullRunActivation = previousBareOpen
		openKubernetesObservabilityFullRunActivation = previousObservabilityOpen
		writeFullRunExecutorTerminalMarker = previousWriter
	}()

	verified := bareClusterCreateManifestReceipt()
	prepareCalls := 0
	prepareFullRunExecutionManifest = func(path string) (runner.FullRunExecutionManifestReceipt, error) {
		if path != "/private/bare-run.json" {
			t.Fatalf("manifest path = %q", path)
		}
		prepareCalls++
		return verified, nil
	}
	runs := 0
	openBareClusterFullRunActivation = func(path string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
		if path != "/private/bare-run.json" {
			t.Fatalf("activation input differs: path=%q", path)
		}
		return fullRunActivationRunnerFunc(func(context.Context) (runner.FullRunExecutionActivationReceipt, error) {
				runs++
				execution := runner.FullRunOrchestrationReceipt{
					Format: runner.FullRunOrchestrationReceiptFormat, State: "SUCCEEDED",
					PlanDigest: verified.PlanDigest, CompletionMode: stageplan.CompletionModeBareClusterMVP,
				}
				return runner.FullRunExecutionActivationReceipt{
					Format: runner.FullRunExecutionActivationReceiptFormat, State: "SUCCEEDED",
					Manifest: verified, Execution: &execution,
				}, nil
			}), runner.FullRunExecutionActivationReceipt{
				Format: runner.FullRunExecutionActivationReceiptFormat, State: "PREPARED", Manifest: verified,
			}, nil
	}
	openKubernetesObservabilityFullRunActivation = func(string, string) (fullRunActivationRunner, runner.FullRunExecutionActivationReceipt, error) {
		t.Fatal("Bare-MVP execution opened the unused Observability activation")
		return nil, runner.FullRunExecutionActivationReceipt{}, errors.New("unexpected Observability activation")
	}
	writeFullRunExecutorTerminalMarker = runner.WriteFullRunExecutorTerminalMarker

	markerDirectory := t.TempDir()
	if err := os.Chmod(markerDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(markerDirectory, runner.FullRunExecutorTerminalMarkerName)
	arguments := []string{
		"cluster", "create", "--file", "/private/bare-run.json", "--live", "--execute",
		"--expected-manifest-digest", verified.ManifestDigest,
		"--independent-evidence-public-key", "/private/evidence.pub",
		"--terminal-marker", markerPath,
	}
	var stdout, stderr bytes.Buffer
	if err := run(arguments, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var receipt runner.FullRunExecutionActivationReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if prepareCalls != 2 || runs != 1 || receipt.State != "SUCCEEDED" || string(marker) != "TERMINAL\n" || stderr.Len() != 0 {
		t.Fatalf("CLI did not cross the exact runner boundary: prepare=%d runs=%d receipt=%#v marker=%q stderr=%s",
			prepareCalls, runs, receipt, string(marker), stderr.String())
	}
}
