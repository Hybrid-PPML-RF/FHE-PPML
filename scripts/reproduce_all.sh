#!/usr/bin/env bash
# One entry point for all runtime experiments of the evaluation: Table 4, Table 5 and Figure 5.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

usage() {
  cat <<EOF
Usage: scripts/reproduce_all.sh [options]          (Docker: docker run ... fhe-ppml [options])

Runs the experiments and writes everything to \$RESULTS_DIR ($RESULTS_DIR):
  logs/                     raw logs of every run (a configuration with a complete log is skipped on re-runs)
  table4.tex/.csv           Table 4: runtime of the FHE and the MPC part (100 trees)
  table5.tex/.csv           Table 5: communication per party, vs. Bhardwaj et al. [7]
  figure5.png/.pdf/.csv     Figure 5: runtime vs. [4], [39], MPC-only, [7]
  table_mpc_only.tex/.csv   MPC-only baseline (all depths with --full)
  compare_paper.csv         measured values next to the values printed in the paper
Stages (default: all, in this order):
  fhe        scripts/run_fhe.sh       FHE part, 4 datasets x depths 4-6 x {no bins, 8 bins}   ~2.7 h
  mpc        scripts/run_mpc.sh       MPC part of our protocol, same 24 configurations         ~1.1 h
  baselines  scripts/run_baselines.sh Bhardwaj et al. [7], 1 tree per dataset x depth (x100)   ~1 h
  mpc-only   scripts/run_mpc.sh --program mpconly   MPC-only baseline at the figure depth     ~10 h
             (all depths with --full: ~3 days, dominated by digits)
  results    scripts/make_results.py  tables, figure, comparison with the paper (seconds)
  Times: paper setting (c6i.32xlarge, WAN); single machine: see README.

Options:
  --quick             smoke test: iris, depth 4 only (all stages, a few minutes)
  --stages LIST       comma-separated subset of: fhe,mpc,baselines,mpc-only,results
  --datasets LIST     datasets (default: "$ALL_DATASETS")
  --depths LIST       depths for Table 4/5 (default: "$ALL_DEPTHS")
  --figure-depth D    tree depth shown in Figure 5 (default: 4); the MPC-only stage runs this depth only
  --full              MPC-only stage at all depths (table_mpc_only)
  --fhe-modes LIST    FHE selection-vector update, default 0 (public model, Table 4);
                      "0 2" also runs the private model (results/fhe_private_model.csv)
  --cpus LIST         pin FHE runs to these CPUs (e.g. 0-47 = the 48 vCPUs of the paper)
  --netem-delay D     emulate WAN latency (e.g. 25ms) on the loopback device during the MPC and baseline
                      stages (single machine only; Docker: --cap-add NET_ADMIN); see scripts/wan_emulation.sh
  --netem-rate R      with --netem-delay: bandwidth limit (e.g. 5gbit)
  --party-id I --hosts FILE [--ssl-dir DIR]
                      multi-machine mode: this machine is MPC party I of the parties in FILE. The MPC stages
                      run first on all machines; party 0 then runs fhe, baselines and results.
  --fill-missing-from-paper   plot values of missing runs from the paper (marked) instead of leaving gaps
  --results DIR       results directory (default: $RESULTS_DIR)
  --force             re-run configurations even if their logs are complete
  --dry-run           print the commands of the run stages only
  -h, --help          this help
EOF
}

STAGES="fhe,mpc,baselines,mpc-only,results"
DATASETS=$ALL_DATASETS DEPTHS=$ALL_DEPTHS FIG_DEPTH=4 FULL=0 FHE_MODES=0 CPUS=""
NETEM_DELAY="" NETEM_RATE="" PARTY_ID="" HOSTS="" SSL_DIR="" FILL=0 FORCE=0 DRY=0 QUICK=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --quick)        QUICK=1; shift ;;
    --stages)       STAGES=$2; shift 2 ;;
    --datasets)     DATASETS=$(norm_list "$2"); shift 2 ;;
    --depths)       DEPTHS=$(norm_list "$2"); shift 2 ;;
    --figure-depth) FIG_DEPTH=$2; shift 2 ;;
    --full)         FULL=1; shift ;;
    --fhe-modes)    FHE_MODES=$(norm_list "$2"); shift 2 ;;
    --cpus)         CPUS=$2; shift 2 ;;
    --netem-delay)  NETEM_DELAY=$2; shift 2 ;;
    --netem-rate)   NETEM_RATE=$2; shift 2 ;;
    --party-id)     PARTY_ID=$2; shift 2 ;;
    --hosts)        HOSTS=$2; shift 2 ;;
    --ssl-dir)      SSL_DIR=$2; shift 2 ;;
    --fill-missing-from-paper) FILL=1; shift ;;
    --results)      RESULTS_DIR=$2; shift 2 ;;
    --force)        FORCE=1; shift ;;
    --dry-run)      DRY=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done
export RESULTS_DIR
if [[ $QUICK == 1 ]]; then DATASETS=iris DEPTHS=4 FIG_DEPTH=4; fi
STAGES=",$(echo "$STAGES" | tr -d ' '),"
for s in $(echo "$STAGES" | tr ',' ' '); do
  check_list stage "fhe mpc baselines mpc-only results" "$s"
done
has() { [[ $STAGES == *",$1,"* ]]; }
MULTI=0
[[ -n $PARTY_ID || -n $HOSTS ]] && MULTI=1
[[ $MULTI == 1 && -n $NETEM_DELAY ]] && die "--netem-delay is for single-machine runs; the multi-machine setup has a real network"
LEADER=1
[[ $MULTI == 1 && $PARTY_ID != 0 ]] && LEADER=0

COMMON=(--datasets "$DATASETS" --results "$RESULTS_DIR")
[[ $FORCE == 1 ]] && COMMON+=(--force)
[[ $DRY == 1 ]] && COMMON+=(--dry-run)
MPC_NET=()
[[ $MULTI == 1 ]] && MPC_NET=(--party-id "$PARTY_ID" --hosts "$HOSTS")
[[ -n $SSL_DIR ]] && MPC_NET+=(--ssl-dir "$SSL_DIR")
MPC_ONLY_DEPTHS=$FIG_DEPTH
[[ $FULL == 1 ]] && MPC_ONLY_DEPTHS=$DEPTHS
FHE_EXTRA=()
[[ -n $CPUS ]] && FHE_EXTRA=(--cpus "$CPUS")

netem() {   # netem on|off
  [[ -z $NETEM_DELAY || $DRY == 1 ]] && return 0
  if [[ $1 == on ]]; then
    "$SCRIPTS_DIR/wan_emulation.sh" on --delay "$NETEM_DELAY" ${NETEM_RATE:+--rate "$NETEM_RATE"} || die "could not enable netem"
  else
    "$SCRIPTS_DIR/wan_emulation.sh" off >/dev/null
  fi
}
trap 'netem off' EXIT

FAILED=()
SUMMARY=()
stage() {   # stage <name> <command...>
  local name=$1 start rc
  shift
  info "======== stage $name: $*"
  start=$(date +%s)
  "$@"; rc=$?
  SUMMARY+=("$(printf '%-10s %-6s %6d s' "$name" "$([[ $rc == 0 ]] && echo ok || echo FAILED)" $(( $(date +%s) - start )))")
  [[ $rc == 0 ]] || FAILED+=("$name")
  # refresh tables and figure with what is there so far (cheap)
  if [[ $DRY == 0 && $LEADER == 1 && $name != results ]] && has results; then make_results >/dev/null 2>&1 || true; fi
}
make_results() {
  local args=(--results "$RESULTS_DIR" --figure-depth "$FIG_DEPTH")
  [[ $FILL == 1 ]] && args+=(--fill-missing-from-paper)
  python3 "$SCRIPTS_DIR/make_results.py" "${args[@]}"
}

[[ $DRY == 0 ]] && { mkdir -p "$RESULTS_DIR" || die "cannot create $RESULTS_DIR"; write_run_info "reproduce_all.sh stages=$STAGES datasets=[$DATASETS] depths=[$DEPTHS] figure_depth=$FIG_DEPTH full=$FULL"; }
T0=$(date +%s)

run_mpc_stages() {
  netem on
  has mpc && stage mpc "$SCRIPTS_DIR/run_mpc.sh" --program ours "${COMMON[@]}" --depths "$DEPTHS" ${MPC_NET[@]+"${MPC_NET[@]}"}
  if [[ $MULTI == 0 ]] && has baselines; then
    stage baselines "$SCRIPTS_DIR/run_baselines.sh" "${COMMON[@]}" --depths "$DEPTHS"
  fi
  has mpc-only && stage mpc-only "$SCRIPTS_DIR/run_mpc.sh" --program mpconly "${COMMON[@]}" --depths "$MPC_ONLY_DEPTHS" ${MPC_NET[@]+"${MPC_NET[@]}"}
  netem off
}

if [[ $MULTI == 0 ]]; then
  has fhe && stage fhe "$SCRIPTS_DIR/run_fhe.sh" "${COMMON[@]}" --depths "$DEPTHS" --modes "$FHE_MODES" ${FHE_EXTRA[@]+"${FHE_EXTRA[@]}"}
  run_mpc_stages
else
  run_mpc_stages
  if [[ $LEADER == 1 ]]; then
    has fhe && stage fhe "$SCRIPTS_DIR/run_fhe.sh" "${COMMON[@]}" --depths "$DEPTHS" --modes "$FHE_MODES" ${FHE_EXTRA[@]+"${FHE_EXTRA[@]}"}
    has baselines && stage baselines "$SCRIPTS_DIR/run_baselines.sh" "${COMMON[@]}" --depths "$DEPTHS"
  fi
fi
if [[ $LEADER == 1 && $DRY == 0 ]] && has results; then stage results make_results; fi

info "======== summary ($(( $(date +%s) - T0 )) s in total)"
for l in ${SUMMARY[@]+"${SUMMARY[@]}"}; do echo "  $l" >&2; done
if [[ ${#FAILED[@]} -gt 0 ]]; then
  warn "failed stages: ${FAILED[*]} (re-run the same command to retry only the missing configurations)"
  exit 1
fi
[[ $LEADER == 1 && $DRY == 0 ]] && info "results in $RESULTS_DIR (table4.tex, table5.tex, figure5.png, compare_paper.csv)"
exit 0
