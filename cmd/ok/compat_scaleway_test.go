package main

import (
	"bytes"
	"strings"
	"testing"
)

// v1.0.1 + compatibility patch (compat/v1.0.1-scaleway).

func TestCompatValidators(t *testing.T) {
	for _, node := range []string{"scw2", "ok-bm-lab-02", "a"} {
		if err := validateCompatPhysicalNode(node); err != nil {
			t.Fatalf("valid node %q rejected: %v", node, err)
		}
	}
	for _, node := range []string{"Bad_Node", "-x", "x-", "a.b", strings.Repeat("a", 64)} {
		if validateCompatPhysicalNode(node) == nil {
			t.Fatalf("invalid node %q accepted", node)
		}
	}
	for _, pool := range []string{"10.250.0.10-10.250.0.20", "10.250.0.0-10.250.0.255", "192.0.2.1-192.0.2.1"} {
		if err := validateCompatEndpointPool(pool); err != nil {
			t.Fatalf("valid pool %q rejected: %v", pool, err)
		}
	}
	for _, pool := range []string{
		"10.40.0.1-10.40.0.5",     // inside the workload Pod CIDR pool 10.32.0.0/11
		"10.100.0.1-10.100.0.5",   // inside the workload Service CIDR pool 10.96.0.0/12
		"10.31.255.250-10.32.0.5", // spans into 10.32.0.0/11
		"10.250.0.0-10.250.1.0",   // 257 addresses
		"127.0.0.10-127.0.0.20",   // loopback
		"10.250.0.20-10.250.0.10", // reversed
		"10.250.0.10",             // malformed
		"2001:db8::1-2001:db8::2", // IPv6
		"10.250.0.10-",            // malformed
	} {
		if validateCompatEndpointPool(pool) == nil {
			t.Fatalf("invalid pool %q accepted", pool)
		}
	}
}

func TestCompatUnsetIsV101(t *testing.T) {
	t.Setenv(compatPhysicalNodeEnv, "")
	t.Setenv(compatEndpointPoolEnv, "")
	runtime := clusterProvisionRuntime{environmentPath: "/isolated/bin", okLinuxRoot: "/x/ok-linux", managementKubeconfig: "/x/mgmt.yaml"}
	for _, entry := range provisionEnvironment(runtime) {
		if strings.HasPrefix(entry, "OK_COMPAT_") {
			t.Fatalf("compat variable present while unset: %s", entry)
		}
	}
	var out bytes.Buffer
	printCompatBanner(&out)
	if out.Len() != 0 {
		t.Fatalf("banner printed while unset: %q", out.String())
	}
	if err := requireValidCompatEnvironment(); err != nil {
		t.Fatal(err)
	}
}

func TestCompatSetPassesAllowlistAndBanner(t *testing.T) {
	t.Setenv(compatPhysicalNodeEnv, "scw2")
	t.Setenv(compatEndpointPoolEnv, "10.250.0.10-10.250.0.20")
	runtime := clusterProvisionRuntime{environmentPath: "/isolated/bin", okLinuxRoot: "/x/ok-linux", managementKubeconfig: "/x/mgmt.yaml"}
	environment := strings.Join(provisionEnvironment(runtime), "\n")
	if !strings.Contains(environment, "OK_COMPAT_PHYSICAL_NODE=scw2") || !strings.Contains(environment, "OK_COMPAT_ENDPOINT_POOL=10.250.0.10-10.250.0.20") {
		t.Fatalf("compat variables not passed: %s", environment)
	}
	if !strings.Contains(environment, "PATH=/isolated/bin") || strings.Contains(environment, "KUBECONFIG=") && !strings.Contains(environment, "TALOS_INFRA_KUBECONFIG=") {
		t.Fatalf("allowlist otherwise changed: %s", environment)
	}
	var out bytes.Buffer
	printCompatBanner(&out)
	if !strings.Contains(out.String(), "NOT an unmodified v1.0.1 run") || !strings.Contains(out.String(), "scw2") {
		t.Fatalf("banner missing: %q", out.String())
	}
}

func TestCompatInvalidFailsClosed(t *testing.T) {
	t.Setenv(compatPhysicalNodeEnv, "Bad_Node")
	if requireValidCompatEnvironment() == nil {
		t.Fatal("invalid node accepted")
	}
	runtime := clusterProvisionRuntime{environmentPath: "/isolated/bin"}
	for _, entry := range provisionEnvironment(runtime) {
		if strings.HasPrefix(entry, "OK_COMPAT_") {
			t.Fatalf("invalid compat variable passed to the child environment: %s", entry)
		}
	}
	t.Setenv(compatPhysicalNodeEnv, "")
	t.Setenv(compatEndpointPoolEnv, "10.40.0.1-10.40.0.5")
	if requireValidCompatEnvironment() == nil {
		t.Fatal("pool overlapping the workload Pod CIDR pool accepted")
	}
}
