#!/usr/bin/env bash
# Start the reproduction on all MPC machines at once (one MPC party per machine), via ssh + docker.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/launch_multihost.sh --ssh-hosts FILE [options] [-- reproduce_all.sh options]

Runs on every machine i (line i of FILE, party 0 first):
  docker run --rm --network host -v <remote-results>:/results <image> \
      reproduce_all.sh --party-id i --hosts /results/hosts.txt [reproduce_all.sh options]
All machines run the MPC stages together; machine 0 then runs the FHE and baseline stages and builds
the tables and the figure in <remote-results> on machine 0. Output of machine i: launch_logs/party<i>.log.

Requirements: password-less ssh to all machines, Docker usable without sudo on each machine, and the same
image <image> on each machine (build it once and copy it, e.g.
  docker save fhe-ppml | gzip | ssh <host> 'gunzip | docker load'
so that all machines also share the same SSL certificates), TCP ports 14000-15999 open between them.

Options:
  --ssh-hosts FILE       ssh targets (user@host), one per line, in party order
  --mpc-hosts FILE       addresses the parties use to reach each other (default: ssh hosts without "user@";
                         use the private IPs if the machines are in peered VPCs)
  --image NAME           Docker image (default: fhe-ppml)
  --remote-results DIR   results directory on the machines (default: results, relative to the remote home)
  --ssh-opts STR         extra ssh options (default: "-o StrictHostKeyChecking=accept-new")
  --dry-run              print the commands only
  -h, --help             this help
Example (quick test on 10 machines, then the full run):
  scripts/launch_multihost.sh --ssh-hosts hosts_ssh.txt -- --quick --stages mpc,results
  scripts/launch_multihost.sh --ssh-hosts hosts_ssh.txt
EOF
}

SSH_HOSTS="" MPC_HOSTS="" IMAGE=fhe-ppml REMOTE_RESULTS=results SSH_OPTS="-o StrictHostKeyChecking=accept-new" DRY=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --ssh-hosts) SSH_HOSTS=$2; shift 2 ;;
    --mpc-hosts) MPC_HOSTS=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --remote-results) REMOTE_RESULTS=$2; shift 2 ;;
    --ssh-opts) SSH_OPTS=$2; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) echo "unknown option $1 (see --help)" >&2; exit 1 ;;
  esac
done
[[ -f $SSH_HOSTS ]] || { echo "--ssh-hosts FILE is required" >&2; exit 1; }
HOSTS=()
while read -r line; do HOSTS+=("$line"); done < <(grep -v '^[[:space:]]*\(#\|$\)' "$SSH_HOSTS")   # (bash 3 compatible)
N=${#HOSTS[@]}
TMP=$(mktemp)
if [[ -n $MPC_HOSTS ]]; then
  grep -v '^[[:space:]]*\(#\|$\)' "$MPC_HOSTS" > "$TMP"
else
  printf '%s\n' "${HOSTS[@]}" | sed 's/^.*@//' > "$TMP"
fi
[[ $(wc -l < "$TMP") -eq $N ]] || { echo "ssh hosts and MPC hosts differ in length" >&2; exit 1; }
# shellcheck disable=SC2206
SSH=(ssh $SSH_OPTS)
ARGS=""
[[ $# -gt 0 ]] && ARGS=$(printf ' %q' "$@")
mkdir -p launch_logs
echo "Launching $N parties (image $IMAGE), reproduce_all.sh options:${ARGS:- (none)}"
pids=()
for ((i = 0; i < N; i++)); do
  h=${HOSTS[$i]}
  remote="mkdir -p $REMOTE_RESULTS && cd $REMOTE_RESULTS && cat > hosts.txt && docker run --rm --network host \
-v \"\$PWD\":/results $IMAGE reproduce_all.sh --party-id $i --hosts /results/hosts.txt$ARGS"
  if [[ $DRY == 1 ]]; then echo "ssh $h '$remote' < hosts"; continue; fi
  "${SSH[@]}" "$h" "$remote" < "$TMP" > "launch_logs/party$i.log" 2>&1 &
  pids+=($!)
done
rm -f "$TMP"
[[ $DRY == 1 ]] && exit 0
rc=0
for ((i = 0; i < N; i++)); do
  if wait "${pids[$i]}"; then echo "party $i: done"; else echo "party $i: FAILED (launch_logs/party$i.log)"; rc=1; fi
done
echo "Results (tables, figure) on ${HOSTS[0]}:~/$REMOTE_RESULTS"
exit $rc
