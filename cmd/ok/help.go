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
