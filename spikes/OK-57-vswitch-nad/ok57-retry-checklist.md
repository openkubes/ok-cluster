# OK-57 — Checklist for the second attempt (host bridge + NAD spike)

Precondition for everything below: **coordinated maintenance window with Daniel**
(shared infra — node IPs are vSwitch IPs, kubelet↔apiserver runs over this path).

## Before touching anything

- [ ] Maintenance window agreed, Daniel informed, no e2e runs scheduled
- [ ] `./ok57-bridge-cutover.sh baseline` on ok-gpu — **must be green** (arping + nc to `.2:9345`)
      If baseline is already red, the problem predates the spike — stop and diagnose first.
- [ ] `okb && kubectl get nodes` — both Ready
- [ ] Note current ARP state on both hosts: `ip neigh show | grep 192.168.100`
- [ ] Test IPs in `ok57-spike.yaml` (.60/.61) checked against lbPool in cluster-config.yaml

## Cutover (ok-gpu)

- [ ] `./ok57-bridge-cutover.sh cutover`
      (creates br-vswitch with pinned port MAC + MTU 1400, moves .3, sends GARP, self-verifies)
- [ ] `kubectl get nodes -w` for ~2 min — ok-gpu stays Ready
- [ ] If verify FAILs: `./ok57-bridge-cutover.sh rollback`, capture tcpdump evidence
      (`tcpdump -eni <if> arp` on both hosts), attach to OK-57, stop.

## Spike proper (only if cutover PASSes)

- [ ] `kubectl apply -f ok57-spike.yaml`
- [ ] Testplan Stage A (pod): local host, cross-DC both directions, .202, MTU 1372/1472
- [ ] Testplan Stage B (VM): same matrix from inside the Fedora guest
- [ ] Key open question this answers: does the vSwitch forward **VM MACs**
      (foreign MACs beyond the pinned host MAC)? Stage A/B pod+VM traffic is the test.
      Note: Hetzner vSwitch MAC limit is 32 per server port.

## Afterwards

- [ ] Green → persist bridge config (systemd-networkd/netplan → later ok-linux profile),
      same conversion planned for ok-infra, findings → ADR-Platform-012, then
      cluster-base.yaml.tpl + render.py work begins
- [ ] Red → rollback, tcpdump findings as OK-57 comment, park again
- [ ] Either way: `kubectl delete -f ok57-spike.yaml`, results commented on OK-57

## Rollback (any time)

    ./ok57-bridge-cutover.sh rollback

If the peer still can't be reached after rollback: stale ARP entry on ok-infra —
self-heals in 2-5 min, or `ip neigh flush dev enp6s0.4000` on ok-infra.
