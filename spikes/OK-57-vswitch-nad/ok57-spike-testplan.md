# OK-57 Spike — Testplan

Context: validate bridge-type NAD on Hetzner vSwitch (VLAN 4000) before touching
`cluster-base.yaml.tpl` / `render.py`. All resources live in `ok57-spike.yaml`,
cleanup = `kubectl delete -f ok57-spike.yaml`.

## 0. Preflight (host level, on ok-gpu via SSH)

    ip -d link show br-vswitch     # exists, mtu 1400
    ip addr show br-vswitch        # 192.168.100.3/24 on the bridge itself
    bridge link                    # enp4s0.4000 enslaved

On ok-infra: check whether .2 still sits on the VLAN sub-interface or already on
a bridge. If it's still on `enp6s0.4000` directly, that's fine for this spike —
the VM lives on ok-gpu; ok-infra host-bridge migration is a separate step.

## A. Pod smoke test (fast signal, ~30s)

    okb                                          # KUBECONFIG -> ok-infra (RKE2 host)
    kubectl apply -f ok57-spike.yaml
    kubectl -n kubevirt exec -it ok57-nettest-pod -- bash

Inside the pod (should have net1 = 192.168.100.61, MTU 1400):

    ip addr show net1
    ping -c3 192.168.100.3          # local host over the bridge  <- macvlan killer test
    ping -c3 192.168.100.2          # cross-DC to ok-infra        <- old DC7->DC13 path
    ping -c3 192.168.100.202        # Ollama MetalLB IP
    ping -c3 -M do -s 1372 192.168.100.2    # MTU check: 1372+28 = 1400, must pass
    ping -c3 -M do -s 1472 192.168.100.2    # must FAIL (frag needed) -> proves 1400 limit
    curl -m5 http://192.168.100.202:11434/api/tags   # Ollama reachable end-to-end

If A fails: problem is NAD/bridge/vSwitch level — no point booting the VM.
tcpdump on the host to localize:

    # on ok-gpu:    tcpdump -ni br-vswitch icmp
    # on ok-infra:  tcpdump -ni enp6s0.4000 icmp   (or br-* if already bridged)
    # request seen on ok-infra but no reply back on ok-gpu => same asymmetry class
    #   as the old DC7->DC13 issue -> check rp_filter and vSwitch MAC learning

## B. VM test (the actual OK-57 shape)

    kubectl -n kubevirt get vmi ok57-testvm -w      # wait for Running
    virtctl -n kubevirt console ok57-testvm         # login fedora / ok57spike

Inside the VM:

    ip addr show eth1               # 192.168.100.60/24, mtu 1400
    ping -c3 192.168.100.3
    ping -c3 192.168.100.2
    ping -c3 192.168.100.202
    ping -c3 -M do -s 1372 192.168.100.2
    curl -m5 http://192.168.100.202:11434/api/tags

Reverse direction (from ok-gpu host shell):

    ping -c3 192.168.100.60         # host -> VM over the bridge
    # and from ok-infra:
    ping -c3 192.168.100.60         # cross-DC host -> VM

## C. Pass criteria (all must hold)

- [ ] VM/pod -> local host (.3) works        (rules out macvlan-style hairpin issue)
- [ ] VM/pod -> remote host (.2) works both directions (no DC asymmetry)
- [ ] VM/pod -> Ollama (.202) works incl. curl (MetalLB path from VM side)
- [ ] 1372-byte DF ping passes, 1472 fails   (MTU 1400 clean end-to-end)
- [ ] ok-infra -> VM (.60) works             (needed for future MetalLB/ingress paths)

Green => proceed to cluster-base.yaml.tpl + render.py (OK-57 tasks 2-3),
document as spike result in ADR-Platform-012.
Red   => attach tcpdump findings to OK-57, park; OK-56 path stays untouched.

## Cleanup

    kubectl delete -f ok57-spike.yaml
