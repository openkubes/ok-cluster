package jsonstrict

import (
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateAndUnknownFields(t *testing.T) {
	type document struct {
		Name string `json:"name"`
	}
	for name, raw := range map[string]string{
		"duplicate": `{"name":"one","name":"two"}`,
		"unknown":   `{"name":"one","extra":true}`,
		"trailing":  `{"name":"one"} {"name":"two"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var value document
			if err := Decode([]byte(raw), &value); err == nil {
				t.Fatal("unsafe JSON was accepted")
			}
		})
	}
}

func TestDecodeAcceptsNestedJSON(t *testing.T) {
	var value struct {
		Items []map[string]int `json:"items"`
	}
	if err := Decode([]byte(`{"items":[{"value":1}]}`), &value); err != nil {
		t.Fatal(err)
	}
	if got := value.Items[0]["value"]; got != 1 {
		t.Fatalf("value = %d", got)
	}
	if err := Decode([]byte(`{"items":[{"value":1,"value":2}]}`), &value); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected nested duplicate error, got %v", err)
	}
}
