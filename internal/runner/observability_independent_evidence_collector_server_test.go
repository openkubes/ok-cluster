package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

type fixedCollectorAutonomyObserver struct {
	observation ObservabilityCollectorAutonomyObservation
	calls       int
}

func (observer *fixedCollectorAutonomyObserver) Observe(_ context.Context, _ ObservabilityIndependentEvidenceCollectionRequest) (ObservabilityCollectorAutonomyObservation, error) {
	observer.calls++
	return observer.observation, nil
}

type independentCollectorServerMaterial struct {
	server       *ObservabilityIndependentEvidenceCollectorServer
	config       ObservabilityIndependentEvidenceCollectorServerConfig
	identity     ObservabilityCapabilityObservationIdentity
	alertName    string
	webhookToken string
	queryToken   string
	clock        *time.Time
	autonomy     *fixedCollectorAutonomyObserver
}

func TestIndependentCollectorPersistsAndReturnsExactAlertDelivery(t *testing.T) {
	material := newIndependentCollectorServerMaterial(t)
	webhook := performCollectorWebhook(t, material, material.identity, material.webhookToken)
	if webhook.Code != http.StatusCreated {
		t.Fatalf("webhook returned %d: %s", webhook.Code, webhook.Body.String())
	}
	entries, err := os.ReadDir(material.config.StateDirectory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("durable delivery record differs: entries=%d err=%v", len(entries), err)
	}

	response := performCollectorQuery(t, material, material.identity, material.queryToken)
	if response.Code != http.StatusOK {
		t.Fatalf("query returned %d: %s", response.Code, response.Body.String())
	}
	var document ObservabilityIndependentEvidenceCollectionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if !document.ReceiverDeliveryObserved || !document.ClusterLocalServicesReady || document.ExternalClusterDependencies != 0 ||
		document.ReceiverIdentityDigest != material.server.receiverIdentity || document.AutonomyProfileDigest != material.autonomy.observation.AutonomyProfileDigest || material.autonomy.calls != 1 {
		t.Fatalf("collector response differs: %#v calls=%d", document, material.autonomy.calls)
	}

	reopened, err := OpenObservabilityIndependentEvidenceCollectorServer(material.config)
	if err != nil {
		t.Fatal(err)
	}
	material.server = reopened
	replay := performCollectorWebhook(t, material, material.identity, material.webhookToken)
	if replay.Code != http.StatusCreated {
		t.Fatalf("idempotent webhook replay returned %d", replay.Code)
	}
	entries, _ = os.ReadDir(material.config.StateDirectory)
	if len(entries) != 1 {
		t.Fatalf("webhook replay added state: %d", len(entries))
	}
}

func TestIndependentCollectorFailsClosedForForeignDeliveryAndStaleHistory(t *testing.T) {
	material := newIndependentCollectorServerMaterial(t)
	foreign := material.identity
	foreign.FixtureDigest = "sha256:not-a-digest"
	response := performCollectorWebhook(t, material, foreign, material.webhookToken)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("foreign correlation returned %d", response.Code)
	}
	entries, _ := os.ReadDir(material.config.StateDirectory)
	if len(entries) != 0 {
		t.Fatalf("foreign correlation persisted state: %d", len(entries))
	}

	if response := performCollectorWebhook(t, material, material.identity, material.webhookToken); response.Code != http.StatusCreated {
		t.Fatalf("valid webhook returned %d", response.Code)
	}
	advanced := material.clock.Add(11 * time.Minute)
	*material.clock = advanced
	query := performCollectorQuery(t, material, material.identity, material.queryToken)
	var document ObservabilityIndependentEvidenceCollectionResponse
	if query.Code != http.StatusOK || json.Unmarshal(query.Body.Bytes(), &document) != nil || document.ReceiverDeliveryObserved {
		t.Fatalf("stale historical delivery was accepted: code=%d document=%#v", query.Code, document)
	}
}

func TestIndependentCollectorSeparatesWebhookAndQueryAuthority(t *testing.T) {
	material := newIndependentCollectorServerMaterial(t)
	if response := performCollectorWebhook(t, material, material.identity, material.queryToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("query token authorized webhook: %d", response.Code)
	}
	if response := performCollectorQuery(t, material, material.identity, material.webhookToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("webhook token authorized query: %d", response.Code)
	}
	entries, _ := os.ReadDir(material.config.StateDirectory)
	if len(entries) != 0 || material.autonomy.calls != 0 {
		t.Fatalf("unauthorized request reached state or observer: entries=%d calls=%d", len(entries), material.autonomy.calls)
	}
}

func TestIndependentCollectorRejectsUnsafeRuntimeBinding(t *testing.T) {
	material := newIndependentCollectorServerMaterial(t)
	t.Run("shared token", func(t *testing.T) {
		config := material.config
		config.QueryTokenFile = config.WebhookTokenFile
		if _, err := OpenObservabilityIndependentEvidenceCollectorServer(config); err == nil {
			t.Fatal("shared webhook/query authority was accepted")
		}
	})
	t.Run("public state", func(t *testing.T) {
		config := material.config
		if err := os.Chmod(config.StateDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenObservabilityIndependentEvidenceCollectorServer(config); err == nil {
			t.Fatal("public collector state directory was accepted")
		}
	})
}

func newIndependentCollectorServerMaterial(t *testing.T) independentCollectorServerMaterial {
	t.Helper()
	root := t.TempDir()
	stateDirectory := filepath.Join(root, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	webhookToken := "ok147-webhook-token-0123456789abcdef"
	queryToken := "ok147-query-token-0123456789abcdefgh"
	webhookTokenFile := filepath.Join(root, "webhook-token")
	queryTokenFile := filepath.Join(root, "query-token")
	if err := os.WriteFile(webhookTokenFile, []byte(webhookToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queryTokenFile, []byte(queryToken), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, _ := StandardObservabilityCapabilityCheckProfile("ok-observability")
	now := time.Date(2026, 8, 21, 19, 30, 0, 0, time.UTC)
	autonomy := &fixedCollectorAutonomyObserver{observation: ObservabilityCollectorAutonomyObservation{
		ClusterLocalServicesReady: true, ExternalClusterDependencies: 0, AutonomyProfileDigest: digest.SHA256([]byte("bounded-autonomy-profile")),
	}}
	config := ObservabilityIndependentEvidenceCollectorServerConfig{
		WebhookTokenFile: webhookTokenFile, QueryTokenFile: queryTokenFile, StateDirectory: stateDirectory,
		ReceiverName: "ok147-independent-evidence", Profile: profile, MaximumRecordAge: 10 * time.Minute,
		Clock: func() time.Time { return now }, AutonomyObserver: autonomy,
	}
	server, err := OpenObservabilityIndependentEvidenceCollectorServer(config)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := observabilityCapabilityRun(observabilityProbeRequest(), "ok-observability")
	fixture, _ := BuildObservabilitySyntheticFixture(run, capabilityFixtureConfig())
	identity := ObservabilityCapabilityObservationIdentity{
		RunID: run.RunID, TargetClusterUID: run.TargetClusterUID, FixtureDigest: fixture.FixtureDigest, ProfileDigest: profile.Digest(),
	}
	config.Clock = func() time.Time { return now }
	return independentCollectorServerMaterial{
		server: server, config: config, identity: identity, alertName: profile.alertName,
		webhookToken: webhookToken, queryToken: queryToken, clock: &now, autonomy: autonomy,
	}
}

func performCollectorWebhook(t *testing.T, material independentCollectorServerMaterial, identity ObservabilityCapabilityObservationIdentity, token string) *httptest.ResponseRecorder {
	t.Helper()
	payload := map[string]any{
		"version": "4", "groupKey": "synthetic", "status": "firing", "receiver": material.config.ReceiverName,
		"groupLabels": map[string]string{"alertname": material.alertName}, "commonLabels": map[string]string{}, "commonAnnotations": map[string]string{}, "externalURL": "https://redacted.invalid",
		"alerts": []any{map[string]any{
			"status": "firing", "labels": map[string]string{
				"alertname": material.alertName, "severity": "none", "fixture_digest": identity.FixtureDigest,
				"run_id": identity.RunID, "target_cluster_uid": identity.TargetClusterUID,
			},
			"annotations": map[string]string{}, "startsAt": "2026-08-21T19:30:00Z", "endsAt": "0001-01-01T00:00:00Z", "generatorURL": "https://redacted.invalid", "fingerprint": "abcdef",
		}},
	}
	raw, _ := json.Marshal(payload)
	request := httptest.NewRequest(http.MethodPost, observabilityAlertmanagerWebhookPath, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	material.server.ServeHTTP(response, request)
	return response
}

func performCollectorQuery(t *testing.T, material independentCollectorServerMaterial, identity ObservabilityCapabilityObservationIdentity, token string) *httptest.ResponseRecorder {
	t.Helper()
	document := ObservabilityIndependentEvidenceCollectionRequest{
		Format: ObservabilityIndependentEvidenceCollectionRequestFormat, RunID: identity.RunID, TargetClusterUID: identity.TargetClusterUID,
		FixtureDigest: identity.FixtureDigest, ProfileDigest: identity.ProfileDigest, AlertName: material.alertName,
	}
	raw, _, err := canonicalObservabilityIndependentEvidenceCollectionRequest(document)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, observabilityIndependentEvidenceCollectionPath, bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	material.server.ServeHTTP(response, request)
	return response
}
