#!/usr/bin/env bash
# MPC part of our protocol (Table 4 "MPC", Table 5 "Ours MPC") and the MPC-only baseline (Figure 5),
# with MP-SPDZ's sy-shamir-party.x (Shamir secret sharing with MAC, 10 parties, 128-bit prime).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

usage() {
  cat <<EOF
Usage: scripts/run_mpc.sh [options]

Compiles and runs one MP-SPDZ program per dataset x depth x binning, either with all parties on this
machine (default) or with one party per machine (--party-id/--hosts). Logs:
  \$RESULTS_DIR/logs/mpc/<ours|mpconly>_<dataset>_d<depth>_bin<0|1>/party<i>.log   (+ meta.txt)
Configurations whose log is complete are skipped (resume), unless --force.

Programs (mpc/Programs/Source):
  --program ours     bench_fhe.py n m alpha t d           Gini squarings + argmax of our protocol (default)
  --program mpconly  bench_fhe_naive.py n m alpha t d bin  MPC-only baseline (whole Gini in MPC)
  With bins = 1 the programs use alpha = 8.

Options:
  --datasets LIST   datasets (default: "$ALL_DATASETS")
  --depths LIST     tree depths (default: "$ALL_DEPTHS")
  --bins LIST       0 = sqrt(A) attributes, 1 = + 8 bins (default: "$ALL_BINS")
  --parties N       number of parties (default: 10)
  --lgp BITS        bit length of the prime field (default: 128, as stated in the paper)
  --party-id I      multi-machine mode: run only party I on this machine ...
  --hosts FILE      ... connecting to the parties listed in FILE (one IP/hostname per line, party 0 first,
                    no ports; the same file on every machine). Start the script with the same options on
                    all machines at about the same time (see scripts/launch_multihost.sh).
  --ssl-dir DIR     copy the certificates P<i>.pem/P<i>.key from DIR first (must be the same on all machines)
  --port-base P     TCP ports P .. P+999 are used (default: 14000); open them between the machines
  --retries K       re-run a failed configuration up to K times (default: 1)
  --timeout SEC     kill a run after SEC seconds (default: none)
  --cpus LIST       pin the parties to these CPUs (taskset)
  --extra-args STR  extra arguments for sy-shamir-party.x
  --results DIR     results directory (default: \$RESULTS_DIR = $RESULTS_DIR)
  --compile-only    only compile the programs
  --force           re-run configurations that already have a complete log
  --dry-run         only print the commands
  -h, --help        this help

Expected runtimes in the paper's WAN setting (10 x c6i.32xlarge, Oregon/Ohio), per run:
  ours:    iris 25-100 s, wine 45-220 s, cancer 60-460 s, digits 85-730 s  (all 24 runs: about 1.1 h)
  mpconly: iris 120-450 s, wine 260-1200 s, cancer 700-6600 s, digits 10500-93700 s (all 24: about 3 days)
With all 10 parties on one machine the numbers differ (no network latency, but the parties share the CPUs;
mpconly uses 48 threads per party).
EOF
}

PROGRAM=ours DATASETS=$ALL_DATASETS DEPTHS=$ALL_DEPTHS BINS=$ALL_BINS NPARTIES=10 LGP=128
PARTY_ID="" HOSTS="" SSL_DIR="" PORT_BASE=14000 RETRIES=1 TIMEOUT=0 CPUS="" EXTRA=""
COMPILE_ONLY=0 FORCE=0 DRY=0
BIN=sy-shamir-party.x
while [[ $# -gt 0 ]]; do
  case $1 in
    --program)   PROGRAM=$2; shift 2 ;;
    --datasets)  DATASETS=$(norm_list "$2"); shift 2 ;;
    --depths)    DEPTHS=$(norm_list "$2"); shift 2 ;;
    --bins)      BINS=$(norm_list "$2"); shift 2 ;;
    --parties)   NPARTIES=$2; shift 2 ;;
    --lgp)       LGP=$2; shift 2 ;;
    --party-id)  PARTY_ID=$2; shift 2 ;;
    --hosts)     HOSTS=$2; shift 2 ;;
    --ssl-dir)   SSL_DIR=$2; shift 2 ;;
    --port-base) PORT_BASE=$2; shift 2 ;;
    --retries)   RETRIES=$2; shift 2 ;;
    --timeout)   TIMEOUT=$2; shift 2 ;;
    --cpus)      CPUS=$2; shift 2 ;;
    --extra-args) EXTRA=$2; shift 2 ;;
    --results)   RESULTS_DIR=$2; shift 2 ;;
    --compile-only) COMPILE_ONLY=1; shift ;;
    --force)     FORCE=1; shift ;;
    --dry-run)   DRY=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
case $PROGRAM in
  ours) SRC=bench_fhe ;;
  mpconly|naive) PROGRAM=mpconly; SRC=bench_fhe_naive ;;
  *) die "--program must be ours or mpconly" ;;
esac
check_list dataset "$ALL_DATASETS" "$DATASETS"
check_list bins "0 1" "$BINS"
[[ $NPARTIES -le 20 ]] || die "at most 20 parties"
MULTI=0
if [[ -n $PARTY_ID || -n $HOSTS ]]; then
  [[ -n $PARTY_ID && -n $HOSTS ]] || die "--party-id and --hosts go together"
  HOSTS=$(cd "$(dirname "$HOSTS")" && pwd)/$(basename "$HOSTS")
  [[ -f $HOSTS ]] || die "hosts file not found: $HOSTS"
  [[ $(grep -c . "$HOSTS") -ge $NPARTIES ]] || die "$HOSTS lists fewer than $NPARTIES hosts"
  MULTI=1
fi
ME=${PARTY_ID:-0}   # the party whose log decides whether a configuration is complete

# Program arguments of a configuration; the compiled program is named <src>-<args joined by ->.
prog_args() {
  local ds=$1 d=$2 b=$3 n m a t
  n=$(ds_field "$ds" n); m=$(ds_field "$ds" m); a=$(ds_field "$ds" alpha); t=$(ds_field "$ds" t)
  if [[ $PROGRAM == ours ]]; then
    [[ $b == 1 ]] && a=$BIN_ALPHA
    echo "$n $m $a $t $d"
  else
    echo "$n $m $a $t $d $b"      # bench_fhe_naive uses alpha = 8 itself when bin = 1
  fi
}

compile_prog() {   # compile_prog <args...>
  local name sch out
  name="$SRC-$(echo "$*" | tr ' ' '-')"
  sch=$MPSPDZ_DIR/Programs/Schedules/$name.sch
  if [[ -f $sch && $sch -nt $MPSPDZ_DIR/Programs/Source/$SRC.py ]]; then return 0; fi
  if [[ $DRY == 1 ]]; then echo "(cd $MPSPDZ_DIR && python3 ./compile.py $SRC $*)"; return 0; fi
  info "compiling $name"
  out=$(mktemp)
  # shellcheck disable=SC2068
  if ! (cd "$MPSPDZ_DIR" && python3 ./compile.py "$SRC" $@) > "$out" 2>&1; then
    tail -n 20 "$out" >&2; rm -f "$out"; die "compilation of $name failed"
  fi
  grep -E "integer triples|virtual machine rounds" "$out" | sed 's/^ */    /' >&2 || true
  rm -f "$out"
}

# --- compile everything first (keeps the start of the runs in sync between machines) --------------------
for ds in $DATASETS; do for d in $DEPTHS; do for b in $BINS; do
  # shellcheck disable=SC2046
  compile_prog $(prog_args "$ds" "$d" "$b")
done; done; done
[[ $COMPILE_ONLY == 1 ]] && { info "compiled all $PROGRAM programs"; exit 0; }

# --- set up --------------------------------------------------------------------------------------------
[[ -x $MPSPDZ_DIR/$BIN ]] || [[ $DRY == 1 ]] || die "$MPSPDZ_DIR/$BIN not found (build MP-SPDZ, see README)"
PD=$MPSPDZ_DIR/Player-Data
if [[ $DRY == 0 ]]; then
  if [[ -n $SSL_DIR ]]; then
    mkdir -p "$PD"
    cp "$SSL_DIR"/P*.pem "$SSL_DIR"/P*.key "$PD"/
    rm -f "$PD"/*.0; c_rehash "$PD" >/dev/null 2>&1 || openssl rehash "$PD"
  fi
  if [[ $MULTI == 1 ]]; then
    for ((i = 0; i < NPARTIES; i++)); do
      [[ -f $PD/P$i.pem ]] || die "missing $PD/P$i.pem: all machines need the same certificates (--ssl-dir, README)"
    done
    openssl x509 -checkend 0 -noout -in "$PD/P0.pem" >/dev/null || die "certificates in $PD expired; regenerate them once and copy them to all machines"
    ls "$PD"/*.0 >/dev/null 2>&1 || c_rehash "$PD" >/dev/null 2>&1 || openssl rehash "$PD"
  else
    ensure_ssl "$NPARTIES" "$PD"
  fi
  mkdir -p "$RESULTS_DIR/logs/mpc"
  write_run_info "run_mpc.sh program=$PROGRAM datasets=[$DATASETS] depths=[$DEPTHS] bins=[$BINS] parties=$NPARTIES lgp=$LGP" \
    "$([[ $MULTI == 1 ]] && echo "party=$PARTY_ID hosts=$HOSTS" || echo local)"
fi
PREFIX="$(timeout_prefix "$TIMEOUT") $(cpu_prefix "$CPUS")"

run_parties() {   # run_parties <program name> <log dir> <port>; returns 0 if the log of party $ME is complete
  local name=$1 dir=$2 port=$3 i pids=() net
  if [[ $MULTI == 1 ]]; then net="-ip $HOSTS"; else net="-h localhost"; fi
  for ((i = 0; i < NPARTIES; i++)); do
    [[ $MULTI == 1 && $i != "$PARTY_ID" ]] && continue
    # shellcheck disable=SC2086
    (cd "$MPSPDZ_DIR" && exec $PREFIX ./$BIN -p "$i" -N "$NPARTIES" -lgp "$LGP" -pn "$port" $net $EXTRA "$name") \
      > "$dir/party$i.log" 2>&1 &
    pids+=($!)
  done
  for i in "${pids[@]}"; do wait "$i" || true; done
  grep -q "^Time = " "$dir/party$ME.log"
}

LOGROOT=$RESULTS_DIR/logs/mpc
idx=-1 total=0 done_=0 failed=0
for ds in $DATASETS; do for d in $DEPTHS; do for b in $BINS; do
  idx=$((idx + 1)); total=$((total + 1))
  args=$(prog_args "$ds" "$d" "$b")
  name="$SRC-$(echo "$args" | tr ' ' '-')"
  dir=$LOGROOT/${PROGRAM}_${ds}_d${d}_bin${b}
  port=$((PORT_BASE + (idx % 50) * 20))   # a fresh port range per configuration (no cross-talk between runs)
  if [[ $FORCE == 0 && -f $dir/party$ME.log ]] && grep -q "^Time = " "$dir/party$ME.log"; then
    info "skip (done): $(basename "$dir")"; done_=$((done_ + 1)); continue
  fi
  if [[ $DRY == 1 ]]; then
    echo "cd $MPSPDZ_DIR && ./$BIN -p ${PARTY_ID:-<i>} -N $NPARTIES -lgp $LGP -pn $port $([[ $MULTI == 1 ]] && echo "-ip $HOSTS" || echo "-h localhost") $EXTRA $name  > $dir/party${PARTY_ID:-<i>}.log"
    continue
  fi
  ok=0
  for ((attempt = 0; attempt <= RETRIES; attempt++)); do
    rm -rf "$dir.partial"; mkdir -p "$dir.partial"
    cat > "$dir.partial/meta.txt" <<EOF
program=$SRC
args=$args
name=$name
parties=$NPARTIES
lgp=$LGP
mode=$([[ $MULTI == 1 ]] && echo "multi-host party=$PARTY_ID hosts=$HOSTS" || echo local)
port=$port
host=$(hostname)
nproc=$(nproc)
date=$(ts)
attempt=$attempt
EOF
    info "MPC $PROGRAM $ds d=$d bins=$b ($name), attempt $((attempt + 1))"
    start=$(date +%s)
    if run_parties "$name" "$dir.partial" "$port"; then
      echo "wall_s=$(( $(date +%s) - start ))" >> "$dir.partial/meta.txt"
      rm -rf "$dir"; mv "$dir.partial" "$dir"
      info "  done in $(( $(date +%s) - start )) s: $(grep -E '^Time = ' "$dir/party$ME.log") $(grep -E '^Data sent' "$dir/party$ME.log" | cut -d'(' -f1)"
      ok=1; break
    fi
    warn "  attempt failed after $(( $(date +%s) - start )) s, see $dir.partial/party$ME.log"
    tail -n 5 "$dir.partial/party$ME.log" >&2 || true
    sleep 5
  done
  if [[ $ok == 1 ]]; then done_=$((done_ + 1)); else failed=$((failed + 1)); fi
done; done; done
[[ $DRY == 1 ]] && exit 0
info "MPC ($PROGRAM) runs: $done_/$total complete, $failed failed (logs: $LOGROOT)"
[[ $failed == 0 ]]
