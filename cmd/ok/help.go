package main

import (
	"fmt"
	"io"
)

func isHelpArgument(argument string) bool {
	return argument == "help" || argument == "--help" || argument == "-h"
}

func routeHelp(arguments []string, stdout io.Writer) bool {
	if len(arguments) == 0 || (len(arguments) == 1 && isHelpArgument(arguments[0])) {
		writeRootHelp(stdout)
		return true
	}
	helpPrefix := arguments[0] == "help"
	if helpPrefix {
		arguments = arguments[1:]
	}
	if len(arguments) >= 1 && arguments[0] == "config" &&
		(len(arguments) == 1 || len(arguments) == 2 && isHelpArgument(arguments[1]) ||
			len(arguments) >= 2 && (arguments[1] == "init" || arguments[1] == "show") && (helpPrefix || containsFlagHelp(arguments[2:]))) {
		writeConfigHelp(stdout)
		return true
	}
	if len(arguments) == 1 && arguments[0] == "destroy" ||
		len(arguments) == 2 && arguments[0] == "destroy" && isHelpArgument(arguments[1]) {
		writeDestroyHelp(stdout)
		return true
	}
	if len(arguments) >= 2 && arguments[0] == "cluster" && arguments[1] == "destroy" &&
		(len(arguments) == 2 || containsFlagHelp(arguments[2:])) {
		writeDestroyClusterHelp(stdout)
		return true
	}
	if len(arguments) == 1 && arguments[0] == "cluster" ||
		len(arguments) == 2 && arguments[0] == "cluster" && isHelpArgument(arguments[1]) {
		writeClusterHelp(stdout)
		return true
	}
	if len(arguments) == 1 && arguments[0] == "authority" ||
		len(arguments) == 2 && arguments[0] == "authority" && isHelpArgument(arguments[1]) {
		writeAuthorityHelp(stdout)
		return true
	}
	if len(arguments) == 2 && arguments[0] == "authority" && arguments[1] == "stage" ||
		len(arguments) == 3 && arguments[0] == "authority" && arguments[1] == "stage" && isHelpArgument(arguments[2]) {
		writeAuthorityStageHelp(stdout)
		return true
	}
	if len(arguments) == 1 && arguments[0] == "evidence" ||
		len(arguments) == 2 && arguments[0] == "evidence" && isHelpArgument(arguments[1]) {
		writeEvidenceHelp(stdout)
		return true
	}
	if len(arguments) == 2 && arguments[0] == "evidence" && arguments[1] == "observability" ||
		len(arguments) == 3 && arguments[0] == "evidence" && arguments[1] == "observability" && isHelpArgument(arguments[2]) {
		writeEvidenceObservabilityHelp(stdout)
		return true
	}
	if len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "create" && arguments[2] == "requirements" && isHelpArgument(arguments[3]) {
		writeClusterCreateRequirementsHelp(stdout)
		return true
	}
	if len(arguments) >= 3 && arguments[0] == "cluster" && arguments[1] == "create" &&
		(arguments[2] == "render" || arguments[2] == "bind" || arguments[2] == "cluster-template") && containsHelpArgument(arguments[3:]) {
		writeClusterIntentRenderHelp(stdout)
		return true
	}
	if len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "create" && arguments[2] == "manifest-template" && isHelpArgument(arguments[3]) {
		writeClusterCreateManifestTemplateHelp(stdout)
		return true
	}
	if len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "create" && arguments[2] == "plan-template" && isHelpArgument(arguments[3]) {
		writeClusterCreatePlanTemplateHelp(stdout)
		return true
	}
	if len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "create" && arguments[2] == "scaffold" && isHelpArgument(arguments[3]) {
		writeClusterCreateScaffoldHelp(stdout)
		return true
	}
	if len(arguments) >= 2 && arguments[0] == "cluster" && arguments[1] == "create" &&
		(len(arguments) == 2 || containsHelpArgument(arguments[2:])) {
		writeClusterCreateHelp(stdout)
		return true
	}
	if len(arguments) == 2 && arguments[0] == "cluster" && arguments[1] == "stage" ||
		len(arguments) == 3 && arguments[0] == "cluster" && arguments[1] == "stage" && isHelpArgument(arguments[2]) {
		writeClusterStageHelp(stdout)
		return true
	}
	if len(arguments) == 2 && arguments[0] == "cluster" && arguments[1] == "dry-run" ||
		len(arguments) == 3 && arguments[0] == "cluster" && arguments[1] == "dry-run" && isHelpArgument(arguments[2]) {
		writeClusterDryRunHelp(stdout)
		return true
	}
	if len(arguments) == 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" ||
		len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && isHelpArgument(arguments[3]) {
		writeClusterStageRunHelp(stdout)
		return true
	}
	if len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "full" ||
		len(arguments) == 5 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "run" && arguments[3] == "full" && isHelpArgument(arguments[4]) {
		writeClusterStageRunFullHelp(stdout)
		return true
	}
	if len(arguments) == 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" ||
		len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "observe" && isHelpArgument(arguments[3]) {
		writeClusterStageObserveHelp(stdout)
		return true
	}
	if len(arguments) == 3 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "bind" ||
		len(arguments) == 4 && arguments[0] == "cluster" && arguments[1] == "stage" && arguments[2] == "bind" && isHelpArgument(arguments[3]) {
		writeClusterStageBindHelp(stdout)
		return true
	}
	if len(arguments) == 2 && arguments[0] == "version" && isHelpArgument(arguments[1]) {
		fmt.Fprint(stdout, "Usage: ok version\n\nPrint the CLI version and source revision.\n")
		return true
	}
	return false
}

func containsHelpArgument(arguments []string) bool {
	for _, argument := range arguments {
		if isHelpArgument(argument) {
			return true
		}
	}
	return false
}

func containsFlagHelp(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "--help" || argument == "-h" {
			return true
		}
	}
	return false
}

func writeRootHelp(output io.Writer) {
	fmt.Fprint(output, `OpenKubes bounded cluster runner

Usage:
  ok <command> [flags]

Commands:
  cluster     Validate, prepare, and explicitly run cluster workflows
  up          Shorthand for cluster create (same flags and safety gates)
  destroy     Compatibility spelling: ok destroy cluster (prefer ok cluster destroy)
  config      Save and inspect local CLI paths (no cluster contact)
  version     Print version and source revision
  authority   Expert commands for the bounded stage authority
  evidence    Expert commands for independent evidence collection

Run "ok <command> --help" for command-specific help.
`)
}

func writeClusterHelp(output io.Writer) {
	fmt.Fprint(output, `Create, inspect, and explicitly destroy bounded cluster workflows

Usage:
  ok cluster <command> [flags]

Commands:
  create      Validate, prepare, or explicitly execute a Bare-MVP run
  destroy     Interactively tear down a cluster through the existing lifecycle
  stage       Expert stage-level commands
  dry-run     Read-only HTTP validation service (expert)

Start with "ok cluster create --help" or "ok cluster destroy --help".
`)
}

func writeAuthorityHelp(output io.Writer) {
	fmt.Fprint(output, `Prepare and operate the bounded stage authority

Usage:
  ok authority stage <command> [flags]

Commands:
  stage   Build policy and packages or explicitly activate the stage authority

Run "ok authority stage --help" for the expert command boundary.
`)
}

func writeAuthorityStageHelp(output io.Writer) {
	fmt.Fprint(output, `Bounded stage-authority commands

Usage:
  ok authority stage <command> [flags]

Commands:
  policy           Build a Plan-bound authority policy offline
  package          Build an immutable activation package offline
  materialize      Write verified private activation material locally
  launch prepare   Build and review an installation plan offline
  launch execute   Install the exact authority objects; requires --execute
  serve            Run the bounded authority service (Stage-7 signing disabled)

Preparing, packaging, or materializing is not live authorization. Launch
execute is a separate mutation boundary and requires separate approval.
`)
}

func writeEvidenceHelp(output io.Writer) {
	fmt.Fprint(output, `Operate independent evidence services

Usage:
  ok evidence observability <command> [flags]

Commands:
  observability   Serve independently verifiable Observability evidence

Run "ok evidence observability --help" for service-specific help.
`)
}

func writeEvidenceObservabilityHelp(output io.Writer) {
	fmt.Fprint(output, `Serve independent Observability evidence

Usage:
  ok evidence observability serve [flags]

The service is a separate trust domain from the stage authority and runner.
Starting it opens its configured listener; inspect leaf help before launch.
`)
}

func writeClusterDryRunHelp(output io.Writer) {
	fmt.Fprint(output, `Serve the expert read-only validation endpoint

Usage:
  ok cluster dry-run serve [flags]

This is the legacy HTTP validation service. For a one-shot Bare-MVP workflow,
use "ok cluster create --file ... --dry-run".
`)
}

func writeClusterCreateHelp(output io.Writer) {
	fmt.Fprint(output, `Validate cluster intent; manifest execution is currently blocked

Usage:
  ok up cluster-template
  ok up --file cluster.yaml --dry-run
  ok up render --file cluster.yaml --output <new-private-directory>
  ok up --file cluster.yaml --prepare --contract <reviewed-contract.yaml> --output <new-private-directory>
  ok up --file cluster.yaml --prepare --contract <reviewed-contract.yaml> --output <new-private-directory> --runtime-inputs <private-references.json>
  ok up --file cluster.yaml --prepared-dir <existing-preparation> --dry-run
  ok up --file cluster.yaml --prepared-dir <existing-preparation> --live --execute \
    --expected-manifest-digest sha256:<digest> --independent-evidence-public-key <file> \
    --terminal-marker /absolute/private-dir/executor-terminal
  ok up --file <private-manifest.json> --dry-run
  ok up --file <private-manifest.json> --prepare
  ok cluster create requirements
  ok cluster create scaffold --name <new-name> --output <new-private-directory>
  ok cluster create manifest-template
  ok cluster create plan-template
  ok cluster create --file <private-manifest.json> --dry-run
  ok cluster create --file <private-manifest.json> --prepare
  ok cluster create --file <private-manifest.json> --live --execute \
    --expected-manifest-digest sha256:<digest> \
    --independent-evidence-public-key <file> \
    --terminal-marker /absolute/private-dir/executor-terminal

"ok up" is an exact shorthand for "ok cluster create", including preparation
subcommands and legacy contract-planning flags. It does not select a mode, infer
credentials from local config, renew access, or bypass live approval.
Friendly YAML --prepare checks local Contract/projection inputs and generates
credential-free stage artifacts and a verified seven-stage NO-GO plan from the
versioned talos-kubevirt-mvp recipe (only its reviewed E/P revisions). It
requires an explicit reviewed --contract and new --output directory.
Without --runtime-inputs, YAML --prepare exits
non-zero with a static NO-GO receipt. Explicit private 0600 --runtime-inputs may
reference existing credentials and distinct Stage Authority/evidence trust keys;
these files are locally parsed without opening a network client. Only the existing
full-run verifier can complete the handoff as PREPARED_NOT_AUTHORIZED (exit zero).
It does not verify installed RBAC/authority policies, network access or convergence.
Live still requires separate approval for the generated technical JSON manifest.
Flatcar and Ubuntu templates exist, but their bounded runner
integration is not enabled; these profiles do not fall back to Talos.
Optional local paths: --lifecycle-root, --ok-linux-path, --config (or saved paths).
YAML --live requires an existing private --prepared-dir. Its fixture binds the
original normalized YAML to the verified technical manifest. No re-rendering,
implicit preparation, automatic retry or extra executor. --prepared-dir also
supports --dry-run (local credential reads, no API contact), never --prepare or JSON.
All original live gates remain mandatory. No separate binding command is needed.
All options below work with either spelling; technical JSON manifest/evidence requirements
and operation receipts are unchanged. Bare "ok up" only displays this help.

Modes (exactly one is required):
  --dry-run    Verify all bound local inputs and print a non-mutating summary
  --prepare    Validate locally; certificate-bound manifests currently fail closed
  --live       Currently blocked before Stage 1 pending bounded credential bootstrap;
               --execute does not bypass this restriction

Input:
  -f, --file   Private full-run manifest bound to completionMode bare-cluster-mvp/v1

Live inputs:
  --terminal-marker must be an absolute path naming an absent executor-terminal
                    file in an existing private directory (mode 0700 or stricter)

Safety:
  The scaffold command is offline and create-only: it refuses an existing
  output path and writes owner-only templates containing invalid placeholders.
  Dry-run and prepare read and validate referenced private inputs locally, but
  do not contact a cluster, open a network client, or execute a stage.
  Their JSON receipts report apiContacted=false, authorizationConsumed=false,
  mutationAllowed=false, and the next required operator action.
  Current private-manifest --dry-run, --prepare and --live requests reject
  unsupported certificate mode before stages, API calls or grant issuance.
  The same credential dependency blocks downstream Stages 8-12 / PlatformReady.
  No completing Stage 1-7 or Stage 1-12 live workflow is supported yet.

Provider access:
  The lifecycle operator owns provider credential validity and rotation after
  ok exits. The CLI does not renew provider credentials. Offline validation
  does not prove ongoing provider access or future cluster availability.

Legacy contract-planning flags remain available for compatibility; use
"ok cluster stage --help" for the expert runner surface.
`)
}

func writeClusterCreateRequirementsHelp(output io.Writer) {
	fmt.Fprint(output, `Print the machine-readable Bare-MVP input contract

Usage:
  ok cluster create requirements [--format ok-cli-cluster-create-requirements/v1|ok-cli-cluster-create-requirements/v2]

The command reads no file, opens no network client, and emits static JSON for
renderer and packaging integrations. The contract reports that Stage 8-12
post-runtime material is not required for Bare-MVP. It does not prepare or
authorize a run.

The default v1 omits providerAccessOwnership. Explicit v2 includes that
descriptive handoff metadata: the lifecycle operator
owns ongoing provider access; it adds no manifest fields or renewal authority.
Both versions retain the historical workflow schema, including liveMutationAllowed.
That field is not runtime readiness: certificate-bound live execution is blocked.
`)
}

func writeClusterCreateManifestTemplateHelp(output io.Writer) {
	fmt.Fprint(output, `Print a non-authorizing Bare-MVP manifest skeleton

Usage:
  ok cluster create manifest-template

The command reads no file and opens no network client. Its JSON output contains
invalid placeholder identities and paths by design; an authoritative renderer
must replace every placeholder and bind all referenced artifacts before the
result can pass "ok cluster create --file ... --dry-run".
`)
}

func writeClusterCreatePlanTemplateHelp(output io.Writer) {
	fmt.Fprint(output, `Print a non-authorizing seven-stage Bare-MVP plan skeleton

Usage:
  ok cluster create plan-template

The command reads no file and opens no network client. The plan fixes the exact
Stage 1-7 order and authorizationState NO-GO. Its placeholder identities and
digests are deliberately invalid until supplied by an authoritative renderer.
`)
}

func writeClusterCreateScaffoldHelp(output io.Writer) {
	fmt.Fprint(output, `Create a private, non-authorizing Bare-MVP workspace

Usage:
  ok cluster create scaffold --name <new-name> --output <new-private-directory>

The name is used for both the cluster and Contract namespace/name. The output
directory must not exist; scaffold never reuses or overwrites it. It creates
owner-only plan and full-run manifest templates with deliberately invalid
digest and endpoint placeholders. It reads no cluster state, contacts no API,
and grants no mutation authority.
`)
}

func writeClusterStageHelp(output io.Writer) {
	fmt.Fprint(output, `Expert stage-level runner commands

Usage:
  ok cluster stage <command> ...

Command groups:
  attempt     Verify an exact execution attempt
  inspect     Inspect the next plan-bound stage without mutation
  resume      Verify a durable receipt prefix
  run         Prepare or execute bounded stage sequences
  observe     Run bounded read-only observation stages
  bind        Bind runtime identity
  evaluate    Evaluate correlated evidence
  evidence    Produce or package independent evidence
  package     Build an offline activation package
  launch      Prepare or explicitly execute an activation

These commands expose internal safety seams. Most operators should use
"ok cluster create --file ... --dry-run" first.
`)
}

func writeClusterStageRunHelp(output io.Writer) {
	fmt.Fprint(output, `Execute plan-bound stages through the expert runner

Usage:
  ok cluster stage run [flags]
  ok cluster stage run enablement [flags]
  ok cluster stage run target-access [flags]
  ok cluster stage run full prepare [flags]
  ok cluster stage run full execute [flags] --execute

Manual Bare-MVP order across the expert command groups:
  1. cluster stage run                 provider-prerequisites
  2. cluster stage run                 cluster-lifecycle
  3. cluster stage observe lifecycle   lifecycle-observation
  4. cluster stage run enablement      enablement
  5. cluster stage observe network     network-observation
  6. cluster stage bind runtime        runtime-binding
  7. cluster stage run target-access   target-access

Every step is bound to the reviewed Plan and the exact durable receipt prefix.
Mutation-capable execute or launch commands require their own explicit
--execute gate and separate approval. Never replay a stopped or uncertain
mutation; preserve its receipt and inspect the durable state first.

The product private-manifest path is blocked pending bounded credential
bootstrap. Recovery execution is disabled; these flags grant no continuation.
The commands above retain diagnostic and separately supported expert surfaces.
`)
}

func writeClusterStageRunFullHelp(output io.Writer) {
	fmt.Fprint(output, `Inspect or package a manifest-bound runner (live execution currently blocked)

Usage:
  ok cluster stage run full prepare [flags]
  ok cluster stage run full execute [flags] --execute
  ok cluster stage run full package [flags]
  ok cluster stage run full materialize [flags]
  ok cluster stage run full launch prepare [flags]
  ok cluster stage run full launch execute [flags] --execute

Commands:
  prepare          Reject unsupported manifests locally before execution
  execute          Currently rejected before Stage 1
  package          Build the immutable Job-activation package offline
  materialize      Write a verified private execution bundle
  launch prepare   Build and review the four-object installation plan offline
  launch execute   Currently rejected before any activation API request

Current certificate-bound manifests are rejected before Stage 1, APIs or grants.
Prepare/execute and Job launch cannot enable the Stage 1-7 or Stage 1-12 path.
Offline bundle inspection/packaging is not execution readiness. Bounded credential
bootstrap remains an open dependency. Recovery execution is disabled.
`)
}

func writeClusterStageObserveHelp(output io.Writer) {
	fmt.Fprint(output, `Run bounded stage observations

Usage:
  ok cluster stage observe lifecycle [flags]
  ok cluster stage observe network [flags]
  ok cluster stage observe platform [flags]

Commands:
  lifecycle   Observe CAPI/provider lifecycle evidence (Bare-MVP Stage 3)
  network     Observe workload network readiness (Bare-MVP Stage 5)
  platform    Observe post-runtime platform evidence (Stage 11)

Direct observation commands do not repair or reconcile resources. Packaging
and launch subcommands are expert activation paths; a launch execute command
may create its exact activation objects and requires --execute.
`)
}

func writeClusterStageBindHelp(output io.Writer) {
	fmt.Fprint(output, `Bind verified runtime identity

Usage:
  ok cluster stage bind runtime [flags]
  ok cluster stage bind runtime launch prepare [flags]
  ok cluster stage bind runtime launch execute [flags] --execute

The direct runtime command is Bare-MVP Stage 6. It consumes the exact lifecycle
and network receipt prefix and emits bound runtime material. Launch prepare is
offline; launch execute is a separate mutation-capable activation boundary.
`)
}
