#!/usr/bin/env bash
# Optional WAN emulation with tc/netem for runs where all parties are on ONE machine.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/wan_emulation.sh on  [--dev lo] [--delay 25ms] [--jitter 0ms] [--rate RATE]
       scripts/wan_emulation.sh off [--dev lo]
       scripts/wan_emulation.sh status [--dev lo]

Adds a netem queueing discipline to a network device. With all MP-SPDZ parties on one machine they
talk over the loopback device "lo", where every packet is delayed once per direction, i.e. the
round-trip time is 2 x delay. The paper's WAN (Oregon <-> Ohio) has a round-trip time of about 50 ms,
hence the default delay of 25 ms. RATE (e.g. 5gbit) optionally limits the bandwidth.

Caveats: this is an approximation. All party pairs get the same latency, whereas in the paper only the
pairs across the two regions see the WAN latency (5 + 5 machines); the paper's numbers were measured on
real machines (see README, "Multi-machine WAN setup").

Needs root and CAP_NET_ADMIN. In Docker: docker run --cap-add NET_ADMIN ... (the container has its own
loopback device, so the host is not affected). On a host, the emulation affects all local traffic on
the device: turn it off afterwards (scripts/wan_emulation.sh off).
EOF
}

cmd=${1:-}; [[ $# -gt 0 ]] && shift
DEV=lo DELAY=25ms JITTER="" RATE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --dev) DEV=$2; shift 2 ;;
    --delay) DELAY=$2; shift 2 ;;
    --jitter) JITTER=$2; shift 2 ;;
    --rate) RATE=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 1 ;;
  esac
done
[[ $cmd == -h || $cmd == --help || -z $cmd ]] && { usage; exit 0; }
command -v tc >/dev/null || { echo "tc not found (apt-get install iproute2)" >&2; exit 1; }

case $cmd in
  on)
    args=(delay "$DELAY")
    [[ -n $JITTER ]] && args+=("$JITTER")
    [[ -n $RATE ]] && args+=(rate "$RATE")
    # large queue: MP-SPDZ sends big batches; the default netem limit of 1000 packets would drop them
    tc qdisc replace dev "$DEV" root netem "${args[@]}" limit 1000000 \
      || { echo "tc failed: root and CAP_NET_ADMIN needed (docker run --cap-add NET_ADMIN)" >&2; exit 1; }
    echo "netem on $DEV: ${args[*]}"
    ;;
  off)
    tc qdisc del dev "$DEV" root 2>/dev/null || true
    echo "netem off on $DEV"
    ;;
  status)
    tc qdisc show dev "$DEV"
    ;;
  *) usage; exit 1 ;;
esac
