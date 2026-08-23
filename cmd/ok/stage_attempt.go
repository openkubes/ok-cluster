package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/openkubes/ok-cluster/internal/stageattempt"
)

const maximumExecutionAttemptBytes = 64 * 1024

func runClusterStageAttemptVerify(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage attempt verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("attempt", "", "strict redaction-safe execution-attempt document")
	attemptID := flags.String("attempt-id", "", "independently expected attempt identifier")
	sourceFixture := flags.String("source-fixture-digest", "", "independently expected source FixtureDigest")
	sourcePlan := flags.String("source-plan-semantic-digest", "", "independently expected source plan identity")
	runnerImage := flags.String("runner-image", "", "independently expected digest-pinned runner image")
	activationPackage := flags.String("activation-package-digest", "", "independently expected activation package digest")
	predecessorAttempt := flags.String("predecessor-attempt-digest", "", "expected predecessor attempt for recovery")
	stoppedEvidence := flags.String("stopped-evidence-digest", "", "expected stopped evidence for recovery")
	decisionWindow := flags.String("decision-window-digest", "", "independently expected decision-window identity")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, value := range []string{*path, *attemptID, *sourceFixture, *sourcePlan, *runnerImage, *activationPackage, *decisionWindow} {
		if value == "" {
			return errors.New("all non-recovery execution-attempt inputs are required")
		}
	}
	info, err := os.Lstat(*path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumExecutionAttemptBytes {
		return errors.New("execution-attempt document metadata is invalid")
	}
	raw, err := os.ReadFile(*path)
	if err != nil || len(raw) > maximumExecutionAttemptBytes {
		return errors.New("read bounded execution-attempt document")
	}
	receipt, err := stageattempt.Verify(raw, stageattempt.Expected{
		AttemptID: *attemptID, SourceFixtureDigest: *sourceFixture, SourcePlanSemanticDigest: *sourcePlan,
		RunnerImage: *runnerImage, ActivationPackageDigest: *activationPackage,
		PredecessorAttemptDigest: *predecessorAttempt, StoppedEvidenceDigest: *stoppedEvidence,
		DecisionWindowDigest: *decisionWindow,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}
