#!/usr/bin/env bash
# OK-57 spike — host bridge cutover with baseline, MAC pinning and staged rollback.
# Lessons from the aborted 2026-07-09 attempt are baked in:
#   - baseline is measured BEFORE any change (arping/nc, not ping — ICMP unreliable here)
#   - bridge MAC is pinned to the physical port MAC in the same cutover block
#   - gratuitous ARP announced after every IP move
#   - rollback is a single command: ./ok57-bridge-cutover.sh rollback
#
# Run on the node being converted (ok-gpu). Requires: iproute2, arping, nc.
# NOT persistent — a reboot reverts everything. Persistence (networkd/netplan)
# only after the full spike passes, ideally via an ok-linux profile.

set -euo pipefail

### --- adjust per node ---------------------------------------------------
VLAN_IF="enp4s0.4000"          # VLAN sub-interface currently holding the IP
BRIDGE="br-vswitch"
HOST_IP="192.168.100.3/24"
PEER_IP="192.168.100.2"        # remote host used for baseline/verification
PEER_TCP_PORT="9345"           # RKE2 supervisor on ok-infra
MTU="1400"                     # Hetzner vSwitch requirement
### -----------------------------------------------------------------------

PORT_MAC="$(cat "/sys/class/net/${VLAN_IF%%.*}/address")"
IP_ADDR="${HOST_IP%%/*}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

baseline() {
  log "Baseline BEFORE any change (must be green, otherwise abort):"
  arping -c3 -I "$VLAN_IF" "$PEER_IP" || { log "FAIL: peer $PEER_IP does not answer ARP on $VLAN_IF — fix this first, do NOT proceed"; exit 1; }
  nc -zv -w3 "$PEER_IP" "$PEER_TCP_PORT" || { log "FAIL: TCP $PEER_IP:$PEER_TCP_PORT unreachable — fix this first, do NOT proceed"; exit 1; }
  log "Baseline OK."
}

cutover() {
  baseline
  log "Creating $BRIDGE (MAC pinned to $PORT_MAC, MTU $MTU)..."
  ip link add "$BRIDGE" type bridge
  ip link set "$BRIDGE" address "$PORT_MAC"
  ip link set "$BRIDGE" mtu "$MTU"
  ip link set "$BRIDGE" up
  log "Cutover (sub-second interruption)..."
  ip link set "$VLAN_IF" master "$BRIDGE"
  ip addr del "$HOST_IP" dev "$VLAN_IF"
  ip addr add "$HOST_IP" dev "$BRIDGE"
  log "Announcing new binding (gratuitous ARP)..."
  arping -c3 -A -I "$BRIDGE" "$IP_ADDR" || true   # -A gets no replies by design
  verify
}

verify() {
  log "Verification:"
  ip -br addr show "$BRIDGE" || true
  bridge link || true
  arping -c3 -I "$BRIDGE" "$PEER_IP" \
    && nc -zv -w3 "$PEER_IP" "$PEER_TCP_PORT" \
    && log "PASS: vSwitch path healthy on $BRIDGE" \
    || { log "FAIL: vSwitch path broken — run: $0 rollback"; exit 1; }
}

rollback() {
  log "Rolling back to $VLAN_IF..."
  ip link set "$VLAN_IF" nomaster || true
  ip addr del "$HOST_IP" dev "$BRIDGE" 2>/dev/null || true
  ip addr show dev "$VLAN_IF" | grep -q "$IP_ADDR" || ip addr add "$HOST_IP" dev "$VLAN_IF"
  ip link del "$BRIDGE" 2>/dev/null || true
  log "Announcing restored binding (gratuitous ARP)..."
  arping -c3 -A -I "$VLAN_IF" "$IP_ADDR" || true
  log "Verifying restored state:"
  arping -c3 -I "$VLAN_IF" "$PEER_IP" && nc -zv -w3 "$PEER_IP" "$PEER_TCP_PORT" \
    && log "PASS: back to baseline" \
    || log "WARN: peer not reachable yet — stale ARP on peer possible; wait 2-5 min or flush neigh cache on peer"
}

case "${1:-}" in
  baseline) baseline ;;
  cutover)  cutover ;;
  verify)   verify ;;
  rollback) rollback ;;
  *) echo "Usage: $0 {baseline|cutover|verify|rollback}"; exit 1 ;;
esac
