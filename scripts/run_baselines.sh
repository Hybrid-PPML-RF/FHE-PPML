#!/usr/bin/env bash
# Re-measured baseline of Figure 5 / Table 5: Bhardwaj et al., CCS'24 ("[7]"), i.e. their MP-SPDZ implementation
# (https://github.com/data61/MP-SPDZ/pull/1449, head commit of sandy9999/MP-SPDZ), 3 parties, 1 corruption.
# The FHE baselines [4] (Akavia et al.) and [39] (Shin et al.) are NOT re-run: see scripts/baselines_reported.csv.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

usage() {
  cat <<EOF
Usage: scripts/run_baselines.sh [options]

Trains ONE decision tree with the decision-tree trainer of Bhardwaj et al. (their benchmark program
Programs/Source/bench-dt.mpc: n samples, all m attributes, depth d) per dataset x depth, with 3 parties on
this machine. The protocol is data-oblivious, so the runtime and communication do not depend on the data
values; make_results.py multiplies the measured time and communication by the number of trees (100 by
default, --trees in make_results.py) to obtain the cost of the 100-tree random forest.
Logs: \$RESULTS_DIR/logs/baselines/bhardwaj_<dataset>_d<depth>/party<i>.log (+ meta.txt)

Options:
  --datasets LIST   datasets (default: "$ALL_DATASETS")
  --depths LIST     tree depths (default: "$ALL_DEPTHS")
  --protocol P      MP-SPDZ protocol (default: ps-rep-ring = replicated secret sharing over Z_2^k,
                    malicious security with one corruption out of 3; also built: replicated-ring, semi-honest)
  --threads K       threads per party (compile-time argument of bench-dt, default: 48 = vCPUs per
                    server in the paper; lower it on small machines, 3 parties share this machine)
  --ring BITS       ring size for compilation (-R, default: 64)
  --port-base P     TCP ports P .. P+999 (default: 15000)
  --timeout SEC     kill a run after SEC seconds (default: none)
  --cpus LIST       pin the parties to these CPUs (taskset)
  --bhardwaj-dir D  the fork (default: \$BHARDWAJ_DIR = $BHARDWAJ_DIR)
  --results DIR     results directory (default: \$RESULTS_DIR = $RESULTS_DIR)
  --force           re-run configurations that already have a complete log
  --dry-run         only print the commands
  -h, --help        this help

Expected runtime of one tree (from the paper's 100-tree numbers / 100): iris 2-7 s, wine 12-32 s,
cancer 46-66 s, digits 16-23 min. All 12 runs: about 1 h.
EOF
}

DATASETS=$ALL_DATASETS DEPTHS=$ALL_DEPTHS PROTOCOL=ps-rep-ring THREADS=48 RING=64 PORT_BASE=15000
TIMEOUT=0 CPUS="" FORCE=0 DRY=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --datasets) DATASETS=$(norm_list "$2"); shift 2 ;;
    --depths)   DEPTHS=$(norm_list "$2"); shift 2 ;;
    --protocol) PROTOCOL=$2; shift 2 ;;
    --threads)  THREADS=$2; shift 2 ;;
    --ring)     RING=$2; shift 2 ;;
    --port-base) PORT_BASE=$2; shift 2 ;;
    --timeout)  TIMEOUT=$2; shift 2 ;;
    --cpus)     CPUS=$2; shift 2 ;;
    --bhardwaj-dir) BHARDWAJ_DIR=$2; shift 2 ;;
    --results)  RESULTS_DIR=$2; shift 2 ;;
    --force)    FORCE=1; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
check_list dataset "$ALL_DATASETS" "$DATASETS"
BIN=$PROTOCOL-party.x
NP=3
if [[ $DRY == 0 ]]; then
  [[ -x $BHARDWAJ_DIR/$BIN ]] || die "$BHARDWAJ_DIR/$BIN not found (Docker image built with WITH_BASELINES=0? see README)"
  [[ -f $BHARDWAJ_DIR/Programs/Source/bench-dt.mpc ]] || die "$BHARDWAJ_DIR is not the Bhardwaj et al. fork"
  ensure_ssl "$NP" "$BHARDWAJ_DIR/Player-Data"
  mkdir -p "$RESULTS_DIR/logs/baselines"
  write_run_info "run_baselines.sh bhardwaj protocol=$PROTOCOL threads=$THREADS ring=$RING datasets=[$DATASETS] depths=[$DEPTHS]"
fi
PREFIX="$(timeout_prefix "$TIMEOUT") $(cpu_prefix "$CPUS")"

idx=-1 total=0 done_=0 failed=0
for ds in $DATASETS; do
  n=$(ds_field "$ds" n); m=$(ds_field "$ds" m)
  for d in $DEPTHS; do
    idx=$((idx + 1)); total=$((total + 1))
    name=bench-dt-$n-$m-$d-$THREADS
    dir=$RESULTS_DIR/logs/baselines/bhardwaj_${ds}_d${d}
    port=$((PORT_BASE + (idx % 50) * 20))
    if [[ $FORCE == 0 && -f $dir/party0.log ]] && grep -q "^Time = " "$dir/party0.log"; then
      info "skip (done): $(basename "$dir")"; done_=$((done_ + 1)); continue
    fi
    if [[ $DRY == 1 ]]; then
      echo "(cd $BHARDWAJ_DIR && python3 ./compile.py -R $RING bench-dt $n $m $d $THREADS)"
      echo "cd $BHARDWAJ_DIR && ./$BIN -p <i> -pn $port -h localhost $name > $dir/party<i>.log   # i = 0, 1, 2"
      continue
    fi
    sch=$BHARDWAJ_DIR/Programs/Schedules/$name.sch
    if [[ ! -f $sch ]]; then
      info "compiling $name (-R $RING)"
      (cd "$BHARDWAJ_DIR" && python3 ./compile.py -R "$RING" bench-dt "$n" "$m" "$d" "$THREADS") > "$RESULTS_DIR/logs/baselines/compile_$name.log" 2>&1 \
        || { tail -n 20 "$RESULTS_DIR/logs/baselines/compile_$name.log" >&2; die "compilation of $name failed"; }
    fi
    rm -rf "$dir.partial"; mkdir -p "$dir.partial"
    cat > "$dir.partial/meta.txt" <<EOF
baseline=bhardwaj
program=bench-dt
args=$n $m $d $THREADS
name=$name
protocol=$PROTOCOL
ring=$RING
parties=$NP
trees_measured=1
host=$(hostname)
nproc=$(nproc)
date=$(ts)
EOF
    info "Bhardwaj et al. $ds d=$d ($name, $PROTOCOL)"
    start=$(date +%s)
    pids=()
    for ((i = 0; i < NP; i++)); do
      # shellcheck disable=SC2086
      (cd "$BHARDWAJ_DIR" && exec $PREFIX ./$BIN -p "$i" -pn "$port" -h localhost "$name") > "$dir.partial/party$i.log" 2>&1 &
      pids+=($!)
    done
    for p in "${pids[@]}"; do wait "$p" || true; done
    if grep -q "^Time = " "$dir.partial/party0.log"; then
      echo "wall_s=$(( $(date +%s) - start ))" >> "$dir.partial/meta.txt"
      rm -rf "$dir"; mv "$dir.partial" "$dir"
      info "  done in $(( $(date +%s) - start )) s: $(grep -E '^Time = ' "$dir/party0.log") $(grep -E '^Data sent' "$dir/party0.log" | cut -d'(' -f1)"
      done_=$((done_ + 1))
    else
      failed=$((failed + 1))
      warn "  FAILED, see $dir.partial/party0.log"; tail -n 5 "$dir.partial/party0.log" >&2 || true
    fi
  done
done
[[ $DRY == 1 ]] && exit 0
info "Bhardwaj et al. runs: $done_/$total complete, $failed failed"
[[ $failed == 0 ]]
