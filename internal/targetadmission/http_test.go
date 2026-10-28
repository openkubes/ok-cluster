package targetadmission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerEchoesUIDAndValidatesAdmissionContext(t *testing.T) {
	config := policyConfig()
	policy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	for i, object := range config.Objects {
		review := validReviewForObject(config.WriterUsername, object)
		response := sendReview(t, Handler(policy), review)
		if !response.Response.Allowed || response.Response.UID != review.Request.UID || response.Response.Status != nil {
			t.Fatalf("valid exact request %d not allowed with matching UID: %#v", i, response)
		}
	}
	review := validReview(config)

	mutations := map[string]func(*admissionReview){
		"wrong api-server identity": func(value *admissionReview) { value.Request.UserInfo.Username = "system:serviceaccount:other:writer" },
		"wrong group version kind":  func(value *admissionReview) { value.Request.Kind.Kind = "ConfigMap" },
		"wrong resource":            func(value *admissionReview) { value.Request.Resource.Resource = "configmaps" },
		"wrong request resource": func(value *admissionReview) {
			wrong := value.Request.Resource
			wrong.Resource = "configmaps"
			value.Request.RequestResource = &wrong
		},
		"wrong name":      func(value *admissionReview) { value.Request.Name = "other" },
		"wrong namespace": func(value *admissionReview) { value.Request.Namespace = "other" },
		"subresource":     func(value *admissionReview) { value.Request.SubResource = "status" },
		"update":          func(value *admissionReview) { value.Request.Operation = "UPDATE" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := review
			request := *review.Request
			candidate.Request = &request
			mutate(&candidate)
			result := sendReview(t, Handler(policy), candidate)
			if result.Response.Allowed || result.Response.UID != review.Request.UID || result.Response.Status == nil || result.Response.Status.Message != "target-access admission denied" {
				t.Fatalf("mismatched admission request was not denied safely: %#v", result)
			}
		})
	}
}

func TestHandlerMalformedAndUnsupportedRequestsFailClosed(t *testing.T) {
	policy, err := New(policyConfig())
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler(policy)
	t.Run("method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET was accepted: %d", response.Code)
		}
	})
	t.Run("content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
		req.RemoteAddr = "127.0.0.1:12345"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("non-JSON request was accepted: %d", response.Code)
		}
	})
	t.Run("unsupported version", func(t *testing.T) {
		body := []byte(`{"apiVersion":"admission.k8s.io/v1beta1","kind":"AdmissionReview","request":{}}`)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("unsupported AdmissionReview version was accepted: %d", response.Code)
		}
	})
	t.Run("oversized valid review", func(t *testing.T) {
		body, err := json.Marshal(validReview(policyConfig()))
		if err != nil {
			t.Fatal(err)
		}
		if len(body) >= MaxAdmissionReviewBytes {
			t.Fatal("test review unexpectedly exceeds request limit")
		}
		body = append(body, bytes.Repeat([]byte{' '}, MaxAdmissionReviewBytes+1-len(body))...)
		req := httptest.NewRequest(http.MethodPost, AdmissionPath, bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusBadRequest || response.Body.String() != "invalid admission review\n" {
			t.Fatalf("oversized review response = %d %q, want bounded generic 400", response.Code, response.Body.String())
		}
	})
	t.Run("missing policy", func(t *testing.T) {
		review := validReview(policyConfig())
		response := sendReview(t, Handler(nil), review)
		if response.Response.Allowed || response.Response.Status == nil {
			t.Fatal("handler without trusted policy did not fail closed")
		}
	})
}

func sendReview(t *testing.T, handler http.Handler, review admissionReview) admissionReviewResponse {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("valid AdmissionReview got HTTP %d: %s", response.Code, response.Body.String())
	}
	var decoded admissionReviewResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func validReview(config Config) admissionReview {
	return validReviewForObject(config.WriterUsername, config.Objects[0])
}

func validReviewForObject(username string, object Object) admissionReview {
	group, version := splitAPIVersion(object.Identity.APIVersion)
	resourceName := map[string]string{
		"Namespace": "namespaces", "ServiceAccount": "serviceaccounts", "ClusterRole": "clusterroles",
		"ClusterRoleBinding": "clusterrolebindings", "Role": "roles", "RoleBinding": "rolebindings",
	}[object.Identity.Kind]
	return admissionReview{
		APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview",
		Request: &admissionRequest{
			UID: "request-123", Kind: groupVersionKind{Group: group, Version: version, Kind: object.Identity.Kind},
			Resource: groupVersionResource{Group: group, Version: version, Resource: resourceName}, Name: object.Identity.Name,
			Namespace: object.Identity.Namespace, Operation: "CREATE", UserInfo: userInfo{Username: username}, Object: object.Raw,
		},
	}
}
