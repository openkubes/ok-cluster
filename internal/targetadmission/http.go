package targetadmission

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const MaxAdmissionReviewBytes = MaxPolicyBytes + 64*1024

type admissionReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Request    *admissionRequest `json:"request"`
}

type admissionRequest struct {
	UID                string                `json:"uid"`
	Kind               groupVersionKind      `json:"kind"`
	Resource           groupVersionResource  `json:"resource"`
	SubResource        string                `json:"subResource"`
	RequestKind        *groupVersionKind     `json:"requestKind"`
	RequestResource    *groupVersionResource `json:"requestResource"`
	RequestSubResource string                `json:"requestSubResource"`
	Name               string                `json:"name"`
	Namespace          string                `json:"namespace"`
	Operation          string                `json:"operation"`
	UserInfo           userInfo              `json:"userInfo"`
	Object             json.RawMessage       `json:"object"`
	OldObject          json.RawMessage       `json:"oldObject"`
	Options            json.RawMessage       `json:"options"`
	DryRun             *bool                 `json:"dryRun"`
}

type groupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

type groupVersionResource struct {
	Group       string `json:"group"`
	Version     string `json:"version"`
	Resource    string `json:"resource"`
	SubResource string `json:"subresource"`
}

type userInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid"`
	Groups   []string            `json:"groups"`
	Extra    map[string][]string `json:"extra"`
}

type admissionReviewResponse struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Response   *admissionResponse `json:"response"`
}

type admissionResponse struct {
	UID     string           `json:"uid"`
	Allowed bool             `json:"allowed"`
	Status  *admissionStatus `json:"status,omitempty"`
}

type admissionStatus struct {
	Code    int32  `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// Handler serves the decision core as a fail-closed AdmissionReview endpoint.
// It does not establish TLS, authenticate its own deployment, or prove that
// the compiled policy belongs to the API server contacting it.
func Handler(policy *Policy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if policy != nil && !policy.AllowsAPIServerPeer(r.RemoteAddr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxAdmissionReviewBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid admission review", http.StatusBadRequest)
			return
		}
		var review admissionReview
		if err := jsonstrict.Decode(raw, &review); err != nil || review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" || review.Request == nil {
			http.Error(w, "invalid admission review", http.StatusBadRequest)
			return
		}
		request := review.Request
		if request.UID == "" || len(request.UID) > 128 {
			http.Error(w, "invalid admission review", http.StatusBadRequest)
			return
		}
		allowed := policy != nil && request.SubResource == "" && request.RequestSubResource == "" &&
			requestKindMatches(request) && requestResourceMatches(request) && requestMetadataMatches(request) &&
			policy.AdmitCreate(Request{Operation: request.Operation, Username: request.UserInfo.Username, Object: request.Object}) == nil
		status := (*admissionStatus)(nil)
		if !allowed {
			status = &admissionStatus{Code: http.StatusForbidden, Reason: "Forbidden", Message: "target-access admission denied"}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(admissionReviewResponse{
			APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
			Response: &admissionResponse{UID: request.UID, Allowed: allowed, Status: status},
		})
	})
}

func requestKindMatches(request *admissionRequest) bool {
	apiVersion, kind, err := objectType(request.Object)
	if err != nil {
		return false
	}
	group, version := splitAPIVersion(apiVersion)
	want := groupVersionKind{Group: group, Version: version, Kind: kind}
	if request.Kind != want {
		return false
	}
	return request.RequestKind == nil || *request.RequestKind == want
}

func requestResourceMatches(request *admissionRequest) bool {
	apiVersion, kind, err := objectType(request.Object)
	if err != nil {
		return false
	}
	group, version := splitAPIVersion(apiVersion)
	resourceName := map[string]string{
		"Namespace": "namespaces", "ServiceAccount": "serviceaccounts", "ClusterRole": "clusterroles",
		"ClusterRoleBinding": "clusterrolebindings", "Role": "roles", "RoleBinding": "rolebindings",
	}[kind]
	if resourceName == "" {
		return false
	}
	want := groupVersionResource{Group: group, Version: version, Resource: resourceName}
	if request.Resource != want {
		return false
	}
	return request.RequestResource == nil || *request.RequestResource == want
}

func requestMetadataMatches(request *admissionRequest) bool {
	_, identity, err := canonicalObject(request.Object)
	if err != nil {
		return false
	}
	return request.Name == identity.Name && request.Namespace == identity.Namespace
}

func objectType(raw []byte) (string, string, error) {
	_, identity, err := canonicalObject(raw)
	if err != nil {
		return "", "", errors.New("object type is invalid")
	}
	return identity.APIVersion, identity.Kind, nil
}

func splitAPIVersion(value string) (string, string) {
	parts := strings.Split(value, "/")
	if len(parts) == 1 {
		return "", parts[0]
	}
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
