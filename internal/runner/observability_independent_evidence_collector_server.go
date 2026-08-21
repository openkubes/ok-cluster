package runner

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityAlertDeliveryRecordFormat                       = "ok147-observability-alert-delivery-record/v1"
	ObservabilityIndependentEvidenceCollectorServerReceiptFormat = "ok147-observability-independent-evidence-collector-server-receipt/v1"
	observabilityAlertmanagerWebhookPath                         = "/v1/observability/alertmanager-webhook"
	maximumAlertmanagerWebhookBytes                              = 256 * 1024
	maximumAlertDeliveryRecordBytes                              = 32 * 1024
	maximumCollectorTokenBytes                                   = 8 * 1024
)

type ObservabilityIndependentEvidenceCollectorServerReceipt struct {
	Format                 string `json:"format"`
	State                  string `json:"state"`
	ProfileDigest          string `json:"profileDigest"`
	ReceiverIdentityDigest string `json:"receiverIdentityDigest"`
	MaximumRecordAge       string `json:"maximumRecordAge"`
	DurableDeliveryState   string `json:"durableDeliveryState"`
	SeparateAuthorities    bool   `json:"separateAuthorities"`
	MutationAllowed        bool   `json:"mutationAllowed"`
}

type ObservabilityCollectorAutonomyObservation struct {
	ClusterLocalServicesReady   bool
	ExternalClusterDependencies int
	AutonomyProfileDigest       string
}

// ObservabilityCollectorAutonomyObserver is intentionally separate from alert
// delivery. An implementation must independently observe the workload-local
// service set and its external dependencies; the collector never infers this
// claim from webhook delivery or API reachability.
type ObservabilityCollectorAutonomyObserver interface {
	Observe(context.Context, ObservabilityIndependentEvidenceCollectionRequest) (ObservabilityCollectorAutonomyObservation, error)
}

type ObservabilityIndependentEvidenceCollectorServerConfig struct {
	WebhookTokenFile string
	QueryTokenFile   string
	StateDirectory   string
	ReceiverName     string
	Profile          ObservabilityCapabilityCheckProfile
	MaximumRecordAge time.Duration
	Clock            func() time.Time
	AutonomyObserver ObservabilityCollectorAutonomyObserver
}

type ObservabilityIndependentEvidenceCollectorServer struct {
	webhookToken     []byte
	queryToken       []byte
	stateDirectory   string
	receiverName     string
	receiverIdentity string
	profileDigest    string
	alertName        string
	maximumRecordAge time.Duration
	clock            func() time.Time
	autonomy         ObservabilityCollectorAutonomyObserver
}

type observabilityAlertmanagerWebhook struct {
	Version           string                           `json:"version"`
	GroupKey          string                           `json:"groupKey"`
	TruncatedAlerts   int                              `json:"truncatedAlerts,omitempty"`
	Status            string                           `json:"status"`
	Receiver          string                           `json:"receiver"`
	GroupLabels       map[string]string                `json:"groupLabels"`
	CommonLabels      map[string]string                `json:"commonLabels"`
	CommonAnnotations map[string]string                `json:"commonAnnotations"`
	ExternalURL       string                           `json:"externalURL"`
	Alerts            []observabilityAlertmanagerAlert `json:"alerts"`
}

type observabilityAlertmanagerAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     string            `json:"startsAt"`
	EndsAt       string            `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

type observabilityAlertDeliveryRecord struct {
	Format                 string `json:"format"`
	RunID                  string `json:"runId"`
	TargetClusterUID       string `json:"targetClusterUid"`
	FixtureDigest          string `json:"fixtureDigest"`
	ProfileDigest          string `json:"profileDigest"`
	AlertName              string `json:"alertName"`
	ReceiverIdentityDigest string `json:"receiverIdentityDigest"`
	ObservedAt             string `json:"observedAt"`
}

func OpenObservabilityIndependentEvidenceCollectorServer(config ObservabilityIndependentEvidenceCollectorServerConfig) (*ObservabilityIndependentEvidenceCollectorServer, error) {
	standard, err := StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil || config.Clock == nil || config.AutonomyObserver == nil || config.ReceiverName == "" ||
		!runtimeInputUIDPattern.MatchString(config.ReceiverName) || config.Profile.Digest() == "" || config.Profile.Digest() != standard.Digest() ||
		config.MaximumRecordAge < time.Minute || config.MaximumRecordAge > maximumObservabilityIndependentEvidenceWindow {
		return nil, errors.New("observability independent evidence collector server binding is invalid")
	}
	stateInfo, err := os.Lstat(config.StateDirectory)
	if err != nil || !filepath.IsAbs(config.StateDirectory) || filepath.Clean(config.StateDirectory) != config.StateDirectory ||
		!stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 || stateInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("observability independent evidence collector state directory is not private")
	}
	webhookToken, err := readCollectorToken(config.WebhookTokenFile)
	if err != nil {
		return nil, errors.New("read observability collector webhook token")
	}
	queryToken, err := readCollectorToken(config.QueryTokenFile)
	if err != nil || subtle.ConstantTimeCompare(webhookToken, queryToken) == 1 {
		return nil, errors.New("read distinct observability collector query token")
	}
	receiverIdentity := digest.SHA256([]byte("ok147-observability-alert-receiver/v1\n" + config.ReceiverName))
	return &ObservabilityIndependentEvidenceCollectorServer{
		webhookToken: webhookToken, queryToken: queryToken, stateDirectory: config.StateDirectory,
		receiverName: config.ReceiverName, receiverIdentity: receiverIdentity,
		profileDigest: config.Profile.Digest(), alertName: config.Profile.alertName,
		maximumRecordAge: config.MaximumRecordAge, clock: config.Clock, autonomy: config.AutonomyObserver,
	}, nil
}

func (server *ObservabilityIndependentEvidenceCollectorServer) Receipt() (ObservabilityIndependentEvidenceCollectorServerReceipt, error) {
	if server == nil || server.clock == nil || server.autonomy == nil || !platformInputDigestPattern.MatchString(server.profileDigest) ||
		!platformInputDigestPattern.MatchString(server.receiverIdentity) || server.maximumRecordAge < time.Minute {
		return ObservabilityIndependentEvidenceCollectorServerReceipt{}, errors.New("observability independent evidence collector server is invalid")
	}
	return ObservabilityIndependentEvidenceCollectorServerReceipt{
		Format: ObservabilityIndependentEvidenceCollectorServerReceiptFormat, State: "VERIFIED",
		ProfileDigest: server.profileDigest, ReceiverIdentityDigest: server.receiverIdentity,
		MaximumRecordAge: server.maximumRecordAge.String(), DurableDeliveryState: "create-only-local/v1",
		SeparateAuthorities: true, MutationAllowed: false,
	}, nil
}

func (server *ObservabilityIndependentEvidenceCollectorServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if server == nil || server.clock == nil || server.autonomy == nil {
		http.Error(response, "collector unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		http.Error(response, "request not accepted", http.StatusNotFound)
		return
	}
	switch request.URL.Path {
	case observabilityAlertmanagerWebhookPath:
		server.receiveAlertmanagerWebhook(response, request)
	case observabilityIndependentEvidenceCollectionPath:
		server.collectIndependentEvidence(response, request)
	default:
		http.Error(response, "request not accepted", http.StatusNotFound)
	}
}

func (server *ObservabilityIndependentEvidenceCollectorServer) receiveAlertmanagerWebhook(response http.ResponseWriter, request *http.Request) {
	if !collectorAuthorized(request, server.webhookToken) || request.Header.Get("Content-Type") != "application/json" {
		http.Error(response, "request not authorized", http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maximumAlertmanagerWebhookBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumAlertmanagerWebhookBytes {
		http.Error(response, "webhook not accepted", http.StatusBadRequest)
		return
	}
	var webhook observabilityAlertmanagerWebhook
	if err := jsonstrict.Decode(raw, &webhook); err != nil || webhook.Version != "4" || webhook.Receiver != server.receiverName || webhook.TruncatedAlerts != 0 {
		http.Error(response, "webhook not accepted", http.StatusBadRequest)
		return
	}
	var synthetic *observabilityAlertmanagerAlert
	for index := range webhook.Alerts {
		alert := &webhook.Alerts[index]
		if alert.Labels["alertname"] != server.alertName {
			continue
		}
		if synthetic != nil {
			http.Error(response, "ambiguous synthetic delivery", http.StatusConflict)
			return
		}
		synthetic = alert
	}
	if synthetic == nil || webhook.Status == "resolved" || synthetic.Status == "resolved" {
		response.WriteHeader(http.StatusAccepted)
		return
	}
	if webhook.Status != "firing" || synthetic.Status != "firing" || synthetic.Labels["severity"] != "none" {
		http.Error(response, "synthetic delivery state is invalid", http.StatusBadRequest)
		return
	}
	record := observabilityAlertDeliveryRecord{
		Format: ObservabilityAlertDeliveryRecordFormat, RunID: synthetic.Labels["run_id"],
		TargetClusterUID: synthetic.Labels["target_cluster_uid"], FixtureDigest: synthetic.Labels["fixture_digest"],
		ProfileDigest: server.profileDigest, AlertName: server.alertName,
		ReceiverIdentityDigest: server.receiverIdentity, ObservedAt: server.clock().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if !validAlertDeliveryRecord(record) {
		http.Error(response, "synthetic delivery identity is invalid", http.StatusBadRequest)
		return
	}
	if server.persistDelivery(record) != nil {
		http.Error(response, "synthetic delivery was not persisted", http.StatusInternalServerError)
		return
	}
	response.WriteHeader(http.StatusCreated)
}

func (server *ObservabilityIndependentEvidenceCollectorServer) collectIndependentEvidence(response http.ResponseWriter, request *http.Request) {
	if !collectorAuthorized(request, server.queryToken) || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
		http.Error(response, "request not authorized", http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maximumObservabilityIndependentEvidenceCollectionBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumObservabilityIndependentEvidenceCollectionBytes {
		http.Error(response, "collection request not accepted", http.StatusBadRequest)
		return
	}
	var document ObservabilityIndependentEvidenceCollectionRequest
	if err := jsonstrict.Decode(raw, &document); err != nil {
		http.Error(response, "collection request not accepted", http.StatusBadRequest)
		return
	}
	canonical, requestDigest, err := canonicalObservabilityIndependentEvidenceCollectionRequest(document)
	if err != nil || !bytes.Equal(canonical, raw) || document.ProfileDigest != server.profileDigest || document.AlertName != server.alertName {
		http.Error(response, "collection request not permitted", http.StatusForbidden)
		return
	}
	autonomy, err := server.autonomy.Observe(request.Context(), document)
	if err != nil || autonomy.ExternalClusterDependencies < 0 || !platformInputDigestPattern.MatchString(autonomy.AutonomyProfileDigest) {
		http.Error(response, "autonomy evidence unavailable", http.StatusServiceUnavailable)
		return
	}
	delivered := server.deliveryCurrent(document)
	documentResponse := ObservabilityIndependentEvidenceCollectionResponse{
		Format: ObservabilityIndependentEvidenceCollectionResponseFormat, RequestDigest: requestDigest,
		ReceiverDeliveryObserved: delivered, ReceiverIdentityDigest: server.receiverIdentity,
		ClusterLocalServicesReady:   autonomy.ClusterLocalServicesReady,
		ExternalClusterDependencies: autonomy.ExternalClusterDependencies, AutonomyProfileDigest: autonomy.AutonomyProfileDigest,
	}
	responseRaw, err := json.Marshal(documentResponse)
	if err != nil {
		http.Error(response, "collector unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(responseRaw)
}

func (server *ObservabilityIndependentEvidenceCollectorServer) persistDelivery(record observabilityAlertDeliveryRecord) error {
	raw, key, err := canonicalAlertDeliveryRecord(record)
	if err != nil {
		return err
	}
	path := filepath.Join(server.stateDirectory, strings.TrimPrefix(key, "sha256:")+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		stored, readErr := readBoundedRegular(path, maximumAlertDeliveryRecordBytes)
		if readErr != nil || !bytes.Equal(stored, raw) {
			return errors.New("existing alert delivery record differs")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (server *ObservabilityIndependentEvidenceCollectorServer) deliveryCurrent(request ObservabilityIndependentEvidenceCollectionRequest) bool {
	record := observabilityAlertDeliveryRecord{
		Format: ObservabilityAlertDeliveryRecordFormat, RunID: request.RunID, TargetClusterUID: request.TargetClusterUID,
		FixtureDigest: request.FixtureDigest, ProfileDigest: request.ProfileDigest, AlertName: request.AlertName,
		ReceiverIdentityDigest: server.receiverIdentity,
	}
	_, key, err := canonicalAlertDeliveryRecord(record)
	if err != nil {
		return false
	}
	path := filepath.Join(server.stateDirectory, strings.TrimPrefix(key, "sha256:")+".json")
	raw, err := readBoundedRegular(path, maximumAlertDeliveryRecordBytes)
	if err != nil {
		return false
	}
	var stored observabilityAlertDeliveryRecord
	if err := jsonstrict.Decode(raw, &stored); err != nil || !validAlertDeliveryRecord(stored) || stored.RunID != record.RunID ||
		stored.TargetClusterUID != record.TargetClusterUID || stored.FixtureDigest != record.FixtureDigest || stored.ProfileDigest != record.ProfileDigest ||
		stored.AlertName != record.AlertName || stored.ReceiverIdentityDigest != record.ReceiverIdentityDigest {
		return false
	}
	observedAt, err := time.Parse(time.RFC3339, stored.ObservedAt)
	now := server.clock().UTC()
	return err == nil && stored.ObservedAt == observedAt.UTC().Format(time.RFC3339) && !now.Before(observedAt) && now.Sub(observedAt) <= server.maximumRecordAge
}

func canonicalAlertDeliveryRecord(record observabilityAlertDeliveryRecord) ([]byte, string, error) {
	identityRecord := record
	identityRecord.ObservedAt = ""
	if !validAlertDeliveryRecordIdentity(identityRecord) {
		return nil, "", errors.New("alert delivery identity is invalid")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return nil, "", err
	}
	identityRaw, err := json.Marshal(identityRecord)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest.SHA256(identityRaw), nil
}

func validAlertDeliveryRecord(record observabilityAlertDeliveryRecord) bool {
	if !validAlertDeliveryRecordIdentity(record) || record.ObservedAt == "" {
		return false
	}
	observedAt, err := time.Parse(time.RFC3339, record.ObservedAt)
	return err == nil && record.ObservedAt == observedAt.UTC().Format(time.RFC3339)
}

func validAlertDeliveryRecordIdentity(record observabilityAlertDeliveryRecord) bool {
	return record.Format == ObservabilityAlertDeliveryRecordFormat && validObservabilityObservationIdentity(ObservabilityCapabilityObservationIdentity{
		RunID: record.RunID, TargetClusterUID: record.TargetClusterUID, FixtureDigest: record.FixtureDigest, ProfileDigest: record.ProfileDigest,
	}) && record.AlertName != "" && runtimeInputUIDPattern.MatchString(record.AlertName) && platformInputDigestPattern.MatchString(record.ReceiverIdentityDigest)
}

func readCollectorToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("collector token file is not private")
	}
	raw, err := readBoundedRegular(path, maximumCollectorTokenBytes)
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	if err != nil || !validCollectorToken(raw) {
		return nil, errors.New("collector token is invalid")
	}
	return append([]byte(nil), raw...), nil
}

func validCollectorToken(token []byte) bool {
	if len(token) < 32 || len(token) > maximumCollectorTokenBytes || !bytes.Equal(token, bytes.TrimSpace(token)) || bytes.ContainsAny(token, "\r\n") {
		return false
	}
	for _, value := range token {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("._~-", rune(value)) {
			continue
		}
		return false
	}
	return true
}

func collectorAuthorized(request *http.Request, expected []byte) bool {
	presented := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	return presented != request.Header.Get("Authorization") && subtle.ConstantTimeCompare([]byte(presented), expected) == 1
}
