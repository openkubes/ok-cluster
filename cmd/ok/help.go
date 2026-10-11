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
	if arguments[0] == "help" {
		arguments = arguments[1:]
	}
	if len(arguments) == 1 && arguments[0] == "cluster" ||
		len(arguments) == 2 && arguments[0] == "cluster" && isHelpArgument(arguments[1]) {
		writeClusterHelp(stdout)
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
  version     Print version and source revision
  authority   Expert commands for the bounded stage authority
  evidence    Expert commands for independent evidence collection

Run "ok <command> --help" for command-specific help.
`)
}

func writeClusterHelp(output io.Writer) {
	fmt.Fprint(output, `Create and inspect bounded cluster workflows

Usage:
  ok cluster <command> [flags]

Commands:
  create      Validate, prepare, or explicitly execute a Bare-MVP run
  stage       Expert stage-level commands
  dry-run     Read-only HTTP validation service (expert)

Start with "ok cluster create --help".
`)
}

func writeClusterCreateHelp(output io.Writer) {
	fmt.Fprint(output, `Validate, prepare, or execute one bound Bare-MVP cluster run

Usage:
  ok cluster create --file <private-manifest.json> --dry-run
  ok cluster create --file <private-manifest.json> --prepare
  ok cluster create --file <private-manifest.json> --live --execute \
    --expected-manifest-digest sha256:<digest> \
    --independent-evidence-public-key <file> \
    --terminal-marker <private-dir>/executor-terminal

Modes (exactly one is required):
  --dry-run    Verify all bound local inputs and print a non-mutating summary
  --prepare    Verify the manifest and print the identity required for live mode
  --live       Contact bound APIs and permit the exact workflow mutations;
               also requires --execute and the prepared identity

Input:
  -f, --file   Private full-run manifest bound to completionMode bare-cluster-mvp/v1

Live inputs:
  --terminal-marker must name an absent executor-terminal file in an existing
                    private directory (mode 0700 or stricter)

Safety:
  Dry-run and prepare read and validate referenced private inputs locally, but
  do not contact a cluster, open a network client, or execute a stage.
  Their JSON receipts report apiContacted=false, authorizationConsumed=false,
  mutationAllowed=false, and the next required operator action.
  Live mode runs the Stage 1-7 executor locally, may create cluster resources,
  is single-use and bounded, and has no retry, rollback, or cleanup.

Legacy contract-planning flags remain available for compatibility; use
"ok cluster stage --help" for the expert runner surface.
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

The product path "ok cluster create --file ..." is preferred for a complete
Bare-MVP run. The commands above are an expert diagnostic and recovery surface.
`)
}

func writeClusterStageRunFullHelp(output io.Writer) {
	fmt.Fprint(output, `Prepare or execute a complete manifest-bound runner

Usage:
  ok cluster stage run full prepare [flags]
  ok cluster stage run full execute [flags] --execute
  ok cluster stage run full package [flags]
  ok cluster stage run full materialize [flags]
  ok cluster stage run full launch prepare [flags]
  ok cluster stage run full launch execute [flags] --execute

Commands:
  prepare          Verify the complete private manifest offline
  execute          Run the single-use in-process executor against bound APIs
  package          Build the immutable Job-activation package offline
  materialize      Write a verified private execution bundle
  launch prepare   Build and review the four-object installation plan offline
  launch execute   Install the exact activation objects on ok-mgmt

The execute and launch-execute paths are different live boundaries. Both
require separate approval and an explicit --execute gate. Most operators
should use "ok cluster create --file ..." instead of this expert surface.
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
