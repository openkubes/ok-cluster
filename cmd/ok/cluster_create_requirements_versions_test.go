package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRequirementsVersionCompatibility(t *testing.T) {
	outputs := map[string]map[string]json.RawMessage{}
	for _, test := range []struct{ version, format string }{
		{"v1", clusterCreateRequirementsFormat},
		{"v2", clusterCreateRequirementsFormatV2},
	} {
		t.Run(test.version, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run([]string{"cluster", "create", "requirements", "--format", test.format}, &stdout, &stderr); err != nil || stderr.Len() != 0 {
				t.Fatalf("requirements: %v %s", err, stderr.String())
			}
			golden, err := os.ReadFile(filepath.Join("testdata", "requirements-"+test.version+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stdout.Bytes(), golden) {
				t.Fatalf("requirements/%s wire contract changed", test.version)
			}
			var decoded clusterCreateRequirements
			decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatal(err)
			}
			if (decoded.ProviderAccessOwnership != nil) != (test.version == "v2") {
				t.Fatal("ownership metadata escaped its version")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(stdout.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			delete(fields, "format")
			delete(fields, "providerAccessOwnership")
			outputs[test.version] = fields
			if test.version == "v1" {
				var defaults bytes.Buffer
				if err := run([]string{"cluster", "create", "requirements"}, &defaults, &stderr); err != nil || !bytes.Equal(stdout.Bytes(), defaults.Bytes()) {
					t.Fatal("default requirements no longer preserve v1")
				}
			}
		})
	}
	if !reflect.DeepEqual(outputs["v1"], outputs["v2"]) {
		t.Fatal("ownership version changed other requirements")
	}
	for _, args := range [][]string{
		{"--format", "ok-cli-cluster-create-requirements/v3"}, {"--format", "v2"}, {"--format", ""}, {"--format"}, {"--unknown"}, {"extra"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(append([]string{"cluster", "create", "requirements"}, args...), &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatalf("unsupported requirements silently accepted: %v", args)
		}
	}
}
