package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkSuggestRejectsAuthorizingReceipt(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python 3 required for adapter boundary test")
	}
	for _, field := range []string{"runnerReady", "mutationAllowed", "authorizationConsumed", "reservationCreated", "globalAvailabilityProven", "apiContacted", "observedCollisionCheckCompleted", "state", "name"} {
		t.Run(field, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			if err := os.Mkdir(filepath.Join(root, "scripts"), 0o700); err != nil {
				t.Fatal(err)
			}
			receipt := map[string]any{"format": "ok-cli-network-proposal/v1", "state": "PROPOSED_NOT_RESERVED", "name": "my-cluster",
				"proposedNetwork": map[string]string{"endpoint": "192.0.2.11", "podCIDR": "10.32.0.0/16", "serviceCIDR": "10.96.0.0/20"},
				"apiContacted":    false, "observedCollisionCheckCompleted": false, "globalAvailabilityProven": false,
				"reservationCreated": false, "authorizationConsumed": false, "mutationAllowed": false, "runnerReady": false}
			if field == "state" || field == "name" {
				receipt[field] = "foreign"
			} else {
				receipt[field] = true
			}
			raw, _ := json.Marshal(receipt)
			if err := os.WriteFile(filepath.Join(root, "scripts", "suggest_cluster_network.py"), []byte(fmt.Sprintf("import sys\nsys.stdin.read()\nsys.stdout.write(%q)\n", string(raw))), 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "must-not-exist.yaml")
			var stdout bytes.Buffer
			err := run([]string{"up", "network-suggest", "--file", intentFixture(t, nil), "--lifecycle-root", root,
				"--clusters-dir", root, "--endpoint-pool", "192.0.2.1-192.0.2.20", "--output", output}, &stdout, &bytes.Buffer{})
			if err == nil || stdout.Len() != 0 {
				t.Fatal("unsafe receipt returned")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("unsafe proposal wrote YAML")
			}
		})
	}
}

func TestNetworkSuggestHelpAndModes(t *testing.T) {
	for _, prefix := range [][]string{{"up"}, {"cluster", "create"}} {
		var stdout, stderr bytes.Buffer
		args := append(append([]string{}, prefix...), "network-suggest", "--help")
		if err := run(args, &stdout, &stderr); err != nil || stderr.Len() != 0 || !strings.Contains(stdout.String(), "--endpoint-pool") || !strings.Contains(stdout.String(), "not a reservation") {
			t.Fatalf("help: %v %s %s", err, &stdout, &stderr)
		}
		for _, suffix := range [][]string{nil, {"--online", "--endpoint-pool", "192.0.2.1"}, {"--pool", "ns/name"}, {"--execute"}, {"--online", "positional"}} {
			stdout.Reset()
			args := append(append(append([]string{}, prefix...), "network-suggest", "--file", "/must-not-open.yaml"), suffix...)
			if err := run(args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
				t.Fatal("unsafe/missing mode accepted")
			}
		}
	}
}
