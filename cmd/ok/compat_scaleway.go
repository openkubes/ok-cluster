package main

// v1.0.1 + compatibility patch (branch compat/v1.0.1-scaleway; never merged to main).
//
// Two optional operator variables are passed through the otherwise unchanged child-environment
// allowlist. When both are unset, the CLI behaves exactly like v1.0.1.
//   OK_COMPAT_PHYSICAL_NODE  physical Kubernetes node for the logical "ok-infra" scheduling profile
//   OK_COMPAT_ENDPOINT_POOL  "<first-ipv4>-<last-ipv4>" endpoint pool replacing 192.168.100.200-254
// The logical profile, provider identity digest, storage contract and ok-linux pin are not changed.
// Python enforces the same rules (profile_resolvers/compat.py); both layers fail closed.

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
)

const (
	compatPhysicalNodeEnv = "OK_COMPAT_PHYSICAL_NODE"
	compatEndpointPoolEnv = "OK_COMPAT_ENDPOINT_POOL"
)

var compatNodePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

var compatReservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.32.0.0/11"), // workload Pod CIDR pool (render.py)
	netip.MustParsePrefix("10.96.0.0/12"), // workload Service CIDR pool (render.py)
}

func validateCompatPhysicalNode(value string) error {
	if !compatNodePattern.MatchString(value) {
		return fmt.Errorf("%s is not a valid Kubernetes node name", compatPhysicalNodeEnv)
	}
	return nil
}

func validateCompatEndpointPool(value string) error {
	var first, last netip.Addr
	for index := 0; index < len(value); index++ {
		if value[index] != '-' {
			continue
		}
		a, errA := netip.ParseAddr(value[:index])
		b, errB := netip.ParseAddr(value[index+1:])
		if errA == nil && errB == nil {
			first, last = a, b
		}
		break
	}
	if !first.IsValid() || !first.Is4() || !last.Is4() || last.Less(first) {
		return fmt.Errorf("%s must be <first-ipv4>-<last-ipv4> with first <= last", compatEndpointPoolEnv)
	}
	f, l := first.As4(), last.As4()
	size := (uint32(l[0])<<24 | uint32(l[1])<<16 | uint32(l[2])<<8 | uint32(l[3])) -
		(uint32(f[0])<<24 | uint32(f[1])<<16 | uint32(f[2])<<8 | uint32(f[3])) + 1
	if size > 256 {
		return fmt.Errorf("%s must contain at most 256 addresses", compatEndpointPoolEnv)
	}
	for _, address := range []netip.Addr{first, last} {
		if !address.IsGlobalUnicast() {
			return fmt.Errorf("%s contains a non-unicast address %s", compatEndpointPoolEnv, address)
		}
	}
	for _, reserved := range compatReservedPrefixes {
		if reserved.Contains(first) || reserved.Contains(last) ||
			(first.Less(reserved.Addr()) && !last.Less(reserved.Addr())) {
			return fmt.Errorf("%s overlaps the workload CIDR pool %s", compatEndpointPoolEnv, reserved)
		}
	}
	return nil
}

// compatEnvironment returns the validated compatibility variables that are set (empty map = v1.0.1).
func compatEnvironment() (map[string]string, error) {
	values := map[string]string{}
	if value := os.Getenv(compatPhysicalNodeEnv); value != "" {
		if err := validateCompatPhysicalNode(value); err != nil {
			return nil, err
		}
		values[compatPhysicalNodeEnv] = value
	}
	if value := os.Getenv(compatEndpointPoolEnv); value != "" {
		if err := validateCompatEndpointPool(value); err != nil {
			return nil, err
		}
		values[compatEndpointPoolEnv] = value
	}
	return values, nil
}

func requireValidCompatEnvironment() error {
	if _, err := compatEnvironment(); err != nil {
		return errors.New("compatibility patch: " + err.Error())
	}
	return nil
}

func printCompatBanner(output io.Writer) {
	values, err := compatEnvironment()
	if err != nil || len(values) == 0 {
		return
	}
	fmt.Fprintln(output, "COMPATIBILITY MODE: v1.0.1 + Scaleway compatibility patch with Talos image re-pin (compat/v1.0.1-scaleway) - NOT an unmodified v1.0.1 run")
	if node, ok := values[compatPhysicalNodeEnv]; ok {
		fmt.Fprintf(output, "  %s=%s (VMs of the logical profile ok-infra are placed on this node)\n", compatPhysicalNodeEnv, node)
	}
	if pool, ok := values[compatEndpointPoolEnv]; ok {
		fmt.Fprintf(output, "  %s=%s (replaces the endpoint pool 192.168.100.200-254)\n", compatEndpointPoolEnv, pool)
	}
}
