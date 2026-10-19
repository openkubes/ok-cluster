package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/runner"
)

func TestGuidedUpCredentialPolicyGuidanceRetainsErrorIdentity(t *testing.T) {
	for _, cause := range []error{
		runner.ErrClientCertificateDisabled,
		fmt.Errorf("prepared manifest verification failed: %w", runner.ErrClientCertificateDisabled),
	} {
		err := explainGuidedUpCredentialPolicy(cause)
		if !errors.Is(err, runner.ErrClientCertificateDisabled) || !errors.Is(err, cause) {
			t.Fatalf("guidance dropped the original cause: %v", err)
		}
		for _, message := range []string{"blocked", "not enabled yet", "reviewed integration", "no user-side workaround",
			"do not switch to an administrator kubeconfig", "delete retained preparation", "or retry the run", cause.Error()} {
			if !strings.Contains(err.Error(), message) {
				t.Fatalf("missing %q: %v", message, err)
			}
		}
		for _, claim := range []string{"Type ok", "runnerReady=true", "SUCCEEDED", "No cluster API was contacted", "no cluster started"} {
			if strings.Contains(err.Error(), claim) {
				t.Fatalf("guidance invented an outcome/authority claim %q", claim)
			}
		}
	}
}

func TestGuidedUpCredentialPolicyGuidanceDoesNotReclassifyOtherErrors(t *testing.T) {
	for _, err := range []error{nil, io.ErrClosedPipe, errors.New("cancelled"), errors.New(runner.ErrClientCertificateDisabled.Error())} {
		if got := explainGuidedUpCredentialPolicy(err); got != err {
			t.Fatalf("unrelated or lookalike error was reclassified: %v -> %v", err, got)
		}
	}
}
