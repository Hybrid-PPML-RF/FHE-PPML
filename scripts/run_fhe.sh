#!/usr/bin/env bash
# FHE part of our protocol (Table 4, columns "FHE"): runs ./ppml for every dataset x depth x binning.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

usage() {
  cat <<EOF
Usage: scripts/run_fhe.sh [options]

Runs the FHE benchmark (build/ppml, main_integrity.cpp) for all configurations and writes one log per run to
  \$RESULTS_DIR/logs/fhe/fhe_<dataset>_d<depth>_bin<0|1>_mode<mode>_r<rep>.log
Configurations whose log is complete are skipped (resume), unless --force.

  ./ppml <dataset_id> <depth> <is_bin> 1 0 <N> <mode>       (is_sqrt = 1: sqrt(A) attributes per node)

Options:
  --datasets LIST   datasets (default: "$ALL_DATASETS")
  --depths LIST     tree depths (default: "$ALL_DEPTHS")
  --bins LIST       0 = sqrt(A) attributes, 1 = sqrt(A) attributes + 8 bins (default: "$ALL_BINS")
  --modes LIST      selection-vector update (default: 0)
                      0 = split opened (public model) -- what Table 4 reports
                      2 = private model, selection from MPC shares (Sec. "Private Model", optional comparison)
  --repeat K        repetitions per configuration (default: 1; make_results.py averages them)
  --ring N          ring dimension (default: 16384, as in the paper)
  --cpus LIST       pin to these CPUs with taskset, e.g. 0-47 for the 48 vCPUs per server of the paper
  --timeout SEC     kill a run after SEC seconds (default: none)
  --ppml PATH       benchmark binary (default: \$PPML_BIN = $PPML_BIN)
  --results DIR     results directory (default: \$RESULTS_DIR = $RESULTS_DIR)
  --force           re-run configurations that already have a complete log
  --dry-run         only print the commands
  -h, --help        this help

Expected runtimes (paper machine, AWS c6i.32xlarge): iris 15-30 s, wine 20-75 s, cancer 45-330 s,
digits 650-2700 s per run; all 24 runs of Table 4 take about 2.7 h.
EOF
}

DATASETS=$ALL_DATASETS DEPTHS=$ALL_DEPTHS BINS=$ALL_BINS MODES=0 REPEAT=1 RING=16384
CPUS="" TIMEOUT=0 FORCE=0 DRY=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --datasets) DATASETS=$(norm_list "$2"); shift 2 ;;
    --depths)   DEPTHS=$(norm_list "$2"); shift 2 ;;
    --bins)     BINS=$(norm_list "$2"); shift 2 ;;
    --modes|--mode) MODES=$(norm_list "$2"); shift 2 ;;
    --repeat)   REPEAT=$2; shift 2 ;;
    --ring)     RING=$2; shift 2 ;;
    --cpus)     CPUS=$2; shift 2 ;;
    --timeout)  TIMEOUT=$2; shift 2 ;;
    --ppml)     PPML_BIN=$2; shift 2 ;;
    --results)  RESULTS_DIR=$2; shift 2 ;;
    --force)    FORCE=1; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
check_list dataset "$ALL_DATASETS" "$DATASETS"
check_list bins "0 1" "$BINS"
check_list mode "0 1 2" "$MODES"

LOGDIR=$RESULTS_DIR/logs/fhe
if [[ $DRY == 0 ]]; then
  [[ -x $PPML_BIN ]] || die "benchmark binary not found: $PPML_BIN (build it, see README, or pass --ppml)"
  mkdir -p "$LOGDIR"
  write_run_info "run_fhe.sh datasets=[$DATASETS] depths=[$DEPTHS] bins=[$BINS] modes=[$MODES] repeat=$REPEAT cpus=${CPUS:-all}"
fi
PREFIX="$(timeout_prefix "$TIMEOUT") $(cpu_prefix "$CPUS")"

total=0 done_=0 failed=0
for ds in $DATASETS; do
  id=$(ds_field "$ds" id)
  for d in $DEPTHS; do
    for b in $BINS; do
      for mode in $MODES; do
        for ((r = 1; r <= REPEAT; r++)); do
          total=$((total + 1))
          log=$LOGDIR/fhe_${ds}_d${d}_bin${b}_mode${mode}_r${r}.log
          cmd="$PPML_BIN $id $d $b 1 0 $RING $mode"
          if [[ $FORCE == 0 && -f $log ]] && grep -q "^Integrity Runtime for all" "$log"; then
            info "skip (done): $(basename "$log")"
            done_=$((done_ + 1))
            continue
          fi
          if [[ $DRY == 1 ]]; then echo "$PREFIX $cmd > $log"; continue; fi
          info "FHE $ds d=$d bins=$b mode=$mode rep=$r: $cmd"
          start=$(date +%s)
          {
            echo "## cmd: $cmd"
            echo "## host: $(hostname) nproc: $(nproc) cpus: ${CPUS:-all} date: $(ts)"
          } > "$log.partial"
          # shellcheck disable=SC2086
          if $PREFIX $cmd >> "$log.partial" 2>&1 && grep -q "^Integrity Runtime for all" "$log.partial"; then
            echo "## wall_s: $(( $(date +%s) - start ))" >> "$log.partial"
            mv "$log.partial" "$log"
            info "  done in $(( $(date +%s) - start )) s: $(grep 'total runtime' "$log")"
            done_=$((done_ + 1))
          else
            failed=$((failed + 1))
            warn "  FAILED after $(( $(date +%s) - start )) s, see $log.partial"
            tail -n 5 "$log.partial" >&2 || true
          fi
        done
      done
    done
  done
done
[[ $DRY == 1 ]] && exit 0
info "FHE runs: $done_/$total complete, $failed failed (logs: $LOGDIR)"
[[ $failed == 0 ]]
