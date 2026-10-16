package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

// Exercise the built CLI and real manifest loader, with no mocked dispatch or
// preparation function. Every API endpoint is a local fake server. The explicit
// credential error is mandatory, so a different early failure cannot pass.
func TestFullRunCLIRejectsUnsupportedCredentialsBeforeStageOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "ok")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, "../../cmd/ok")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	var apiCalls, mutations, grants atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		if r.Method != http.MethodGet {
			mutations.Add(1)
		}
		if strings.Contains(r.URL.Path, "stage-authorizations") {
			grants.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	for _, version := range []string{"v3-bare", "v4-full"} {
		path, cleanup := fullRunExecutionManifestFixture(t)
		defer cleanup()
		if version == "v4-full" {
			upgradeFullRunExecutionManifestToV4(t, path, runnerStageSHA("5"), runnerStageSHA("5"))
		}
		doc, plan := readFullRunExecutionFixture(t, path)
		if version == "v3-bare" {
			doc.Plan.Expected.CompletionMode = stageplan.CompletionModeBareClusterMVP
			plan["completionMode"] = stageplan.CompletionModeBareClusterMVP
			plan["stages"] = plan["stages"].([]any)[:7]
			writeBundleFile(t, filepath.Dir(doc.Plan.Path), filepath.Base(doc.Plan.Path), mustJSON(t, plan))
		}
		// Isolate every external capability from the retained fixture. These
		// replacements do not need to authenticate: credential mode must be
		// rejected before TLS/material/authority validation or grant resolution.
		raw := mustJSON(t, doc)
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		var isolate func(any)
		isolate = func(v any) {
			switch v := v.(type) {
			case map[string]any:
				for k, child := range v {
					if k == "endpoint" {
						v[k] = server.URL
					} else {
						isolate(child)
					}
				}
			case []any:
				for _, child := range v {
					isolate(child)
				}
			}
		}
		isolate(value)
		raw = mustJSON(t, value)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, command := range [][]string{{"cluster", "create"}, {"up"}, {"cluster", "stage", "run", "full"}} {
			modes := []string{"--dry-run", "--prepare", "--live"}
			if len(command) == 4 {
				modes = []string{"prepare", "execute"}
			}
			for _, mode := range modes {
				t.Run(version+"/"+strings.Join(command, "-")+"/"+mode, func(t *testing.T) {
					markerRoot := t.TempDir()
					if err := os.Chmod(markerRoot, 0o700); err != nil {
						t.Fatal(err)
					}
					marker := filepath.Join(markerRoot, FullRunExecutorTerminalMarkerName)
					args := append(append([]string{}, command...), "--file", path, mode)
					if len(command) == 4 {
						args = append(append([]string{}, command...), mode, "--manifest", path)
					}
					if mode == "--live" || mode == "execute" {
						args = append(args, "--execute", "--expected-manifest-digest", digest.SHA256(raw), "--independent-evidence-public-key", filepath.Join(markerRoot, "unused.pub"), "--terminal-marker", marker)
					}
					cmd := exec.CommandContext(ctx, binary, args...)
					var stdout, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &stdout, &stderr
					if err := cmd.Run(); err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), ErrClientCertificateDisabled.Error()) {
						t.Fatalf("wrong CLI denial: err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
					}
					if apiCalls.Load() != 0 || mutations.Load() != 0 || grants.Load() != 0 {
						t.Fatalf("pre-denial activity: API=%d mutations=%d grants=%d", apiCalls.Load(), mutations.Load(), grants.Load())
					}
					if _, err := os.Lstat(marker); !os.IsNotExist(err) {
						t.Fatalf("rejection wrote terminal marker: %v", err)
					}
					t.Log("explicit credential denial: API requests=0, mutation requests=0, grant requests=0, terminal marker absent")
				})
			}
		}
	}
}
