package runner

import (
	"encoding/json"
	"errors"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const ObservabilityCapabilityCheckProfileFormat = "ok147-observability-capability-check-profile/v1"

type observabilityServiceBinding struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
}

// ObservabilityCapabilityCheckProfile is the closed service and assertion
// identity consumed by the production capability adapter. Its fields are
// deliberately private: callers can select the accepted standard profile,
// but cannot redirect checks to arbitrary Services, Secrets or assertions.
type ObservabilityCapabilityCheckProfile struct {
	format                  string
	namespace               string
	prometheus              observabilityServiceBinding
	grafana                 observabilityServiceBinding
	opensearch              observabilityServiceBinding
	alertmanager            observabilityServiceBinding
	credentialsSecret       string
	grafanaUserKey          string
	grafanaPasswordKey      string
	opensearchPasswordKey   string
	dashboardConfigMap      string
	dashboardUID            string
	prometheusDatasource    string
	alertName               string
	logIndexPattern         string
	requireReceiverDelivery bool
	profileDigest           string
}

type observabilityCapabilityCheckProfileDocument struct {
	Format                  string                      `json:"format"`
	Namespace               string                      `json:"namespace"`
	Prometheus              observabilityServiceBinding `json:"prometheus"`
	Grafana                 observabilityServiceBinding `json:"grafana"`
	OpenSearch              observabilityServiceBinding `json:"openSearch"`
	Alertmanager            observabilityServiceBinding `json:"alertmanager"`
	CredentialsSecret       string                      `json:"credentialsSecret"`
	GrafanaUserKey          string                      `json:"grafanaUserKey"`
	GrafanaPasswordKey      string                      `json:"grafanaPasswordKey"`
	OpenSearchPasswordKey   string                      `json:"openSearchPasswordKey"`
	DashboardConfigMap      string                      `json:"dashboardConfigMap"`
	DashboardUID            string                      `json:"dashboardUid"`
	PrometheusDatasource    string                      `json:"prometheusDatasource"`
	AlertName               string                      `json:"alertName"`
	LogIndexPattern         string                      `json:"logIndexPattern"`
	RequireReceiverDelivery bool                        `json:"requireReceiverDelivery"`
}

// StandardObservabilityCapabilityCheckProfile freezes the accepted
// ok-observability-standard v1 identities. Alert delivery is strict: observing
// a firing alert alone is not a successful delivery check.
func StandardObservabilityCapabilityCheckProfile(namespace string) (ObservabilityCapabilityCheckProfile, error) {
	if namespace != "ok-observability" {
		return ObservabilityCapabilityCheckProfile{}, errors.New("observability capability check namespace is not the standard profile namespace")
	}
	profile := ObservabilityCapabilityCheckProfile{
		format: ObservabilityCapabilityCheckProfileFormat, namespace: namespace,
		prometheus:        observabilityServiceBinding{Name: "ok-observability-prometheus", Port: 9090, Scheme: "http"},
		grafana:           observabilityServiceBinding{Name: "ok-observability-grafana", Port: 80, Scheme: "http"},
		opensearch:        observabilityServiceBinding{Name: "opensearch-cluster-master", Port: 9200, Scheme: "https"},
		alertmanager:      observabilityServiceBinding{Name: "ok-observability-alertmanager", Port: 9093, Scheme: "http"},
		credentialsSecret: "ok-observability-credentials", grafanaUserKey: "grafana-admin-user",
		grafanaPasswordKey: "grafana-admin-password", opensearchPasswordKey: "opensearch-admin-password",
		dashboardConfigMap: "ok-observability-dashboard-platform-overview", dashboardUID: "ok-obs-platform-overview",
		prometheusDatasource: "Prometheus", alertName: "OKObservabilitySyntheticAlert",
		logIndexPattern: "ok-observability-logs*", requireReceiverDelivery: true,
	}
	raw, err := json.Marshal(profile.document())
	if err != nil {
		return ObservabilityCapabilityCheckProfile{}, errors.New("encode observability capability check profile")
	}
	profile.profileDigest = digest.SHA256(raw)
	return profile, nil
}

func (profile ObservabilityCapabilityCheckProfile) Digest() string {
	return profile.profileDigest
}

func (profile ObservabilityCapabilityCheckProfile) document() observabilityCapabilityCheckProfileDocument {
	return observabilityCapabilityCheckProfileDocument{
		Format: profile.format, Namespace: profile.namespace, Prometheus: profile.prometheus,
		Grafana: profile.grafana, OpenSearch: profile.opensearch, Alertmanager: profile.alertmanager,
		CredentialsSecret: profile.credentialsSecret, GrafanaUserKey: profile.grafanaUserKey,
		GrafanaPasswordKey: profile.grafanaPasswordKey, OpenSearchPasswordKey: profile.opensearchPasswordKey,
		DashboardConfigMap: profile.dashboardConfigMap, DashboardUID: profile.dashboardUID,
		PrometheusDatasource: profile.prometheusDatasource, AlertName: profile.alertName,
		LogIndexPattern: profile.logIndexPattern, RequireReceiverDelivery: profile.requireReceiverDelivery,
	}
}
