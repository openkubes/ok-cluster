package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

func decodeObservabilityResponse(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > maximumObservabilityBackendResponseBytes {
		return errors.New("observability response size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errors.New("observability response JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("observability response has trailing content")
	}
	return nil
}

func parsePrometheusMetricPresent(raw []byte, metricName string) (bool, error) {
	var response struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := decodeObservabilityResponse(raw, &response); err != nil || response.Status != "success" {
		return false, errors.New("Prometheus capability response is invalid")
	}
	for _, result := range response.Data.Result {
		if result.Metric["__name__"] == metricName && len(result.Value) == 2 {
			return true, nil
		}
	}
	return false, nil
}

func parseGrafanaPrometheusDatasource(raw []byte, expectedName string) (string, bool, error) {
	var response []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		UID  string `json:"uid"`
	}
	if err := decodeObservabilityResponse(raw, &response); err != nil {
		return "", false, errors.New("Grafana datasource response is invalid")
	}
	uid := ""
	for _, datasource := range response {
		if datasource.Name != expectedName || datasource.Type != "prometheus" {
			continue
		}
		if !grafanaDatasourceUIDPattern.MatchString(datasource.UID) || uid != "" {
			return "", false, errors.New("Grafana Prometheus datasource identity is ambiguous")
		}
		uid = datasource.UID
	}
	return uid, uid != "", nil
}

func parseDashboardProvisioned(raw []byte, namespace, configMapName, dashboardUID string) (bool, error) {
	var response struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := decodeObservabilityResponse(raw, &response); err != nil || response.APIVersion != "v1" || response.Kind != "ConfigMap" ||
		response.Metadata.Namespace != namespace || response.Metadata.Name != configMapName || response.Metadata.Labels["grafana_dashboard"] != "1" || len(response.Data) != 1 {
		return false, errors.New("dashboard capability ConfigMap response is invalid")
	}
	dashboardRaw, ok := response.Data["platform-overview.json"]
	if !ok {
		return false, nil
	}
	var dashboard struct {
		UID string `json:"uid"`
	}
	if err := decodeObservabilityResponse([]byte(dashboardRaw), &dashboard); err != nil {
		return false, errors.New("provisioned dashboard JSON is invalid")
	}
	return dashboard.UID == dashboardUID, nil
}

func parseOpenSearchMarkerPresent(raw []byte) (bool, error) {
	var response struct {
		Hits struct {
			Total json.RawMessage `json:"total"`
		} `json:"hits"`
	}
	if err := decodeObservabilityResponse(raw, &response); err != nil || len(response.Hits.Total) == 0 {
		return false, errors.New("OpenSearch capability response is invalid")
	}
	var object struct {
		Value json.Number `json:"value"`
	}
	if err := decodeObservabilityResponse(response.Hits.Total, &object); err == nil && object.Value != "" {
		value, parseErr := strconv.ParseInt(string(object.Value), 10, 64)
		if parseErr != nil || value < 0 {
			return false, errors.New("OpenSearch hit count is invalid")
		}
		return value > 0, nil
	}
	var number json.Number
	if err := decodeObservabilityResponse(response.Hits.Total, &number); err != nil {
		return false, errors.New("OpenSearch hit count is invalid")
	}
	value, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || value < 0 {
		return false, errors.New("OpenSearch hit count is invalid")
	}
	return value > 0, nil
}

func parseAlertmanagerFiring(raw []byte, alertName string) (bool, error) {
	var response []struct {
		Labels map[string]string `json:"labels"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := decodeObservabilityResponse(raw, &response); err != nil {
		return false, errors.New("Alertmanager capability response is invalid")
	}
	for _, alert := range response {
		if alert.Labels["alertname"] == alertName && alert.Status.State == "active" {
			return true, nil
		}
	}
	return false, nil
}
