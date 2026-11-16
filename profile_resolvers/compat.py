#!/usr/bin/env python3
"""v1.0.1 + compatibility patch (Scaleway lab): optional placement and endpoint-pool overrides.

Unset environment => exactly the v1.0.1 behaviour (logical node == physical node, endpoint pool
192.168.100.200-254). Set only by the operator, passed through the OK CLI child-environment allowlist:

  OK_COMPAT_PHYSICAL_NODE  Kubernetes node name that hosts the VMs of the logical scheduling profile
                           "ok-infra". The logical profile (name, nodeSelector in cluster-config.yaml,
                           provider identity digest, storage contract, ok-linux pin) is unchanged; only VM
                           placement and the node lookups of the lifecycle checks use the physical name.
  OK_COMPAT_ENDPOINT_POOL  "<first-ipv4>-<last-ipv4>" replacing the MetalLB endpoint pool constants
                           (at most 256 addresses, global-unicast IPv4, outside the workload Pod/Service
                           CIDR pools 10.32.0.0/11 and 10.96.0.0/12).
"""
from __future__ import annotations

import ipaddress
import os
import re

NODE_ENV = "OK_COMPAT_PHYSICAL_NODE"
POOL_ENV = "OK_COMPAT_ENDPOINT_POOL"
LOGICAL_NODE = "ok-infra"
_NODE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_RESERVED = (ipaddress.IPv4Network("10.32.0.0/11"), ipaddress.IPv4Network("10.96.0.0/12"))


class CompatError(ValueError):
    """Invalid compatibility-patch input."""


def physical_node(logical: str) -> str:
    """Return the physical node for a logical node selector (identity unless the override is set)."""
    value = os.environ.get(NODE_ENV, "")
    if not value:
        return logical
    if not _NODE.match(value):
        raise CompatError(f"{NODE_ENV} is not a valid Kubernetes node name: {value!r}")
    return value if logical == LOGICAL_NODE else logical


def endpoint_pool(default_first: ipaddress.IPv4Address, default_last: ipaddress.IPv4Address):
    """Return (first, last) of the endpoint pool (the v1.0.1 constants unless the override is set)."""
    value = os.environ.get(POOL_ENV, "")
    if not value:
        return default_first, default_last
    try:
        first_text, last_text = value.split("-")
        first, last = ipaddress.IPv4Address(first_text), ipaddress.IPv4Address(last_text)
    except ValueError as error:
        raise CompatError(f"{POOL_ENV} must be '<first-ipv4>-<last-ipv4>': {value!r}") from error
    size = int(last) - int(first) + 1
    if size < 1 or size > 256:
        raise CompatError(f"{POOL_ENV} must contain 1..256 addresses: {value!r}")
    for address in (first, last):
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified \
                or address.is_reserved:
            raise CompatError(f"{POOL_ENV} contains a non-unicast address: {address}")
    span = ipaddress.summarize_address_range(first, last)
    for network in span:
        for reserved in _RESERVED:
            if network.overlaps(reserved):
                raise CompatError(f"{POOL_ENV} overlaps the workload CIDR pool {reserved}")
    return first, last


def active() -> list[str]:
    """Names of the compatibility overrides that are set (for banners and evidence)."""
    return [name for name in (NODE_ENV, POOL_ENV) if os.environ.get(name)]
