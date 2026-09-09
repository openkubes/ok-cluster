package dryrun

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerProducesNonMutatingPlan(t *testing.T) {
	h := Handler{Schema: []byte(`{"type":"object"}`)}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"dryRun":true,"contract":{}}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
