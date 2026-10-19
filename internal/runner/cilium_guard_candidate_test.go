package runner

import (
	"bytes"
	"errors"
	"regexp"
	"testing"
)

// OFFLINE TEST-ONLY framing experiment. No production adapter calls this code.
// Matching a header does NOT authenticate the Pod, its environment, image or
// transport. The separately reviewed trusted-writer/prevention boundary remains
// mandatory; a forged replacement can print exactly the same header.
func decodeCandidateGuardedProbe(expectedUID string, stdout, stderr []byte, exitCode int) (string, []byte, error) {
	stop := func() (string, []byte, error) {
		return "STOP", nil, errors.New("candidate guard transcript rejected")
	}
	if !regexp.MustCompile(`^[a-z0-9][-a-z0-9]{0,127}$`).MatchString(expectedUID) {
		return stop()
	}
	header := []byte("ok147-uid-guard-candidate/v1:" + expectedUID + "\n")
	if len(stdout) > maximumCiliumExecOutputBytes || len(stderr) > maximumCiliumExecErrorBytes ||
		!bytes.HasPrefix(stdout, header) || exitCode < 0 || exitCode > 255 {
		return stop()
	}
	payload := stdout[len(header):]
	if bytes.Contains(payload, []byte("ok147-uid-guard-candidate/")) {
		return stop()
	}
	// Only after the exact frame has been checked may existing command-failure
	// semantics be considered. In particular, exit 42 with no frame is STOP;
	// the same status from the actual health child is not a guard failure.
	if exitCode != 0 || len(stderr) != 0 {
		return "HEALTH_PENDING", nil, nil
	}
	if len(payload) == 0 {
		return stop()
	}
	// Not SUCCEEDED: the unchanged network evaluator must still validate the
	// health payload and every other required convergence observation.
	return "HEALTH_PAYLOAD_FOR_EVALUATION", bytes.Clone(payload), nil
}

func TestCandidateGuardFrameRejectsBeforeHealthClassification(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	header := "ok147-uid-guard-candidate/v1:" + uid + "\n"
	for _, tc := range []struct {
		name, expected, output string
		stderr                 []byte
		exit                   int
	}{
		{name: "plain health success is not guarded", expected: uid, output: `{"nodes":[]}`},
		{name: "guard rejected UID", expected: uid, exit: 42},
		{name: "missing frame with warmup exit", expected: uid, exit: 1},
		{name: "wrong UID", expected: uid, output: "ok147-uid-guard-candidate/v1:replacement\n{}"},
		{name: "wrong version", expected: uid, output: "ok147-uid-guard-candidate/v2:" + uid + "\n{}"},
		{name: "leading output", expected: uid, output: "noise\n" + header + "{}"},
		{name: "CRLF header", expected: uid, output: "ok147-uid-guard-candidate/v1:" + uid + "\r\n{}"},
		{name: "truncated header", expected: uid, output: header[:len(header)-1]},
		{name: "empty payload", expected: uid, output: header},
		{name: "duplicate frame", expected: uid, output: header + header + "{}"},
		{name: "invalid expected UID", expected: "x\ny", output: header + "{}"},
		{name: "missing expected UID", output: header + "{}"},
		{name: "oversize stdout", expected: uid, output: header + string(make([]byte, maximumCiliumExecOutputBytes))},
		{name: "oversize stderr", expected: uid, output: header + "{}", stderr: make([]byte, maximumCiliumExecErrorBytes+1)},
		{name: "transport failure is not a child exit", expected: uid, output: header + "{}", exit: -1},
		{name: "invalid exit status", expected: uid, output: header + "{}", exit: 256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, raw, err := decodeCandidateGuardedProbe(tc.expected, []byte(tc.output), tc.stderr, tc.exit)
			if state != "STOP" || err == nil || len(raw) != 0 {
				t.Fatalf("invalid frame became health evidence: state=%s bytes=%d err=%v", state, len(raw), err)
			}
		})
	}
}

func TestCandidateGuardFrameSeparatesChildFailureFromGuardFailure(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	framed := []byte("ok147-uid-guard-candidate/v1:" + uid + "\n{}")
	for _, exit := range []int{1, 42, 127} {
		state, raw, err := decodeCandidateGuardedProbe(uid, framed, nil, exit)
		if state != "HEALTH_PENDING" || err != nil || len(raw) != 0 {
			t.Fatalf("framed child exit %d: %s bytes=%d err=%v", exit, state, len(raw), err)
		}
	}
	state, raw, err := decodeCandidateGuardedProbe(uid, framed, []byte("health warmup"), 0)
	if state != "HEALTH_PENDING" || err != nil || len(raw) != 0 {
		t.Fatal("health stderr produced usable success evidence")
	}
}

func TestCandidateGuardFrameReturnsOnlyCopiedPayloadNotSuccess(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	payload := []byte(`{"nodes":[]}`)
	framed := append([]byte("ok147-uid-guard-candidate/v1:"+uid+"\n"), payload...)
	state, raw, err := decodeCandidateGuardedProbe(uid, framed, nil, 0)
	if state != "HEALTH_PAYLOAD_FOR_EVALUATION" || err != nil || !bytes.Equal(raw, payload) {
		t.Fatalf("framed payload: %s %q %v", state, raw, err)
	}
	framed[len(framed)-1] = '!'
	if !bytes.Equal(raw, payload) {
		t.Fatal("payload aliases untrusted transport storage")
	}
	// The frame is intentionally not a JSON/health validator. Invalid health
	// JSON must reach the existing evaluator, never become operation success.
	state, _, err = decodeCandidateGuardedProbe(uid, []byte("ok147-uid-guard-candidate/v1:"+uid+"\nnot-json"), nil, 0)
	if state != "HEALTH_PAYLOAD_FOR_EVALUATION" || err != nil {
		t.Fatal("candidate unexpectedly replaced the health evaluator")
	}
}

func TestCandidateGuardFrameCannotAuthenticateForgedIdentity(t *testing.T) {
	uid := "11111111-2222-4333-8444-555555555555"
	// This is a counterexample, NOT a security pass: a hostile Pod can forge
	// both frame and payload. Framing cannot replace template/writer isolation.
	state, _, err := decodeCandidateGuardedProbe(uid, []byte("ok147-uid-guard-candidate/v1:"+uid+"\n{}"), nil, 0)
	if state != "HEALTH_PAYLOAD_FOR_EVALUATION" || err != nil {
		t.Fatal("counterexample no longer models a syntactically exact forgery")
	}
}
