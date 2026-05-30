#!/usr/bin/env bash
# =============================================================================
# entrypoint.sh — Run related-work private decision tree / random forest
#
# Usage:
#   docker run <image> [OPTIONS]
#
# Options:
#   --algorithm  hamada | abspoel | bhardwaj | mpyc-rf
#                  hamada   : Hamada et al.  PoPETs 2023  (MP-SPDZ TreeTrainer)
#                  abspoel  : Abspoel et al. PoPETs 2021  (MP-SPDZ TreeClassifier)
#                  bhardwaj : Bhardwaj et al. CCS 2024    (MP-SPDZ fork PR #1449)
#                  mpyc-rf  : Abspoel et al. RF variant   (philips-software/MPyC)
#   --dataset    iris | wine | cancer | digits  (default: iris)
#   --depth      tree depth  (default: 6)
#   --num-trees  number of trees; >1 uses rf_train.mpc  (default: 1)
#   --protocol   ring | semi2k  (default: ring)
#   --threads    OMP threads for MP-SPDZ  (default: 1)
#   --help       show this message
#
# Examples:
#   # Single decision tree, Hamada et al., iris, depth 6, 3-party ring
#   docker run <image> --algorithm hamada --dataset iris --depth 6
#
#   # Random forest, 10 trees, wine, depth 4
#   docker run <image> --algorithm hamada --dataset wine --depth 4 --num-trees 10
#
#   # Bhardwaj et al. (if fork was reachable at build time)
#   docker run <image> --algorithm bhardwaj --dataset cancer --depth 5
#
#   # MPyC RF baseline (Abspoel et al. variant)
#   docker run <image> --algorithm mpyc-rf --dataset digits --num-trees 5
# =============================================================================

set -euo pipefail

ALGORITHM="hamada"
DATASET="iris"
DEPTH=6
NUM_TREES=1
PROTOCOL="ring"
THREADS=1

usage() {
    sed -n '3,/^#====/{p}' "$0" | grep '^#' | sed 's/^# \{0,2\}//'
    exit 0
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --algorithm)  ALGORITHM="$2";  shift 2 ;;
        --dataset)    DATASET="$2";    shift 2 ;;
        --depth)      DEPTH="$2";      shift 2 ;;
        --num-trees)  NUM_TREES="$2";  shift 2 ;;
        --protocol)   PROTOCOL="$2";   shift 2 ;;
        --threads)    THREADS="$2";    shift 2 ;;
        --help|-h)    usage ;;
        *) echo "[ERROR] Unknown option: $1" >&2; exit 1 ;;
    esac
done

echo "============================================================"
echo " Related-work runner"
echo "  algorithm : $ALGORITHM"
echo "  dataset   : $DATASET"
echo "  depth     : $DEPTH"
echo "  num_trees : $NUM_TREES"
echo "  protocol  : $PROTOCOL"
echo "  threads   : $THREADS"
echo "============================================================"

# ── MPyC random forest path (separate, no MP-SPDZ) ──────────────────────────
if [[ "$ALGORITHM" == "mpyc-rf" ]]; then
    MPYC_DATA="/tmp/mpyc-data-${DATASET}"
    python3 /opt/related-work/prepare_data.py \
        --dataset "$DATASET" \
        --mpyc-dir "$MPYC_DATA" >&2
    python3 /opt/related-work/run_mpyc_rf.py \
        --dataset   "$DATASET" \
        --num-trees "$NUM_TREES" \
        --depth     "$DEPTH" \
        --data-dir  "$MPYC_DATA"
    exit 0
fi

# ── Select MP-SPDZ installation ──────────────────────────────────────────────
if [[ "$ALGORITHM" == "bhardwaj" ]]; then
    if [[ -f /opt/bhardwaj_status ]] && grep -q "BHARDWAJ_AVAILABLE=1" /opt/bhardwaj_status; then
        MPSPDZ_DIR="/opt/mp-spdz-bhardwaj"
        MPC_PROG="dt_train_bhardwaj"
        echo "[info] Using Bhardwaj et al. fork at $MPSPDZ_DIR"
    else
        echo "[WARN] Bhardwaj fork was unavailable at build time. Falling back to Hamada (main MP-SPDZ)." >&2
        ALGORITHM="hamada"
        MPSPDZ_DIR="/opt/mp-spdz"
        MPC_PROG="dt_train"
    fi
else
    MPSPDZ_DIR="/opt/mp-spdz"
    if [[ "$ALGORITHM" == "abspoel" ]]; then
        MPC_PROG="dt_train_abspoel"
    else
        # hamada (default)
        if [[ "$NUM_TREES" -gt 1 ]]; then
            MPC_PROG="rf_train"
        else
            MPC_PROG="dt_train"
        fi
    fi
fi

# ── Prepare dataset ──────────────────────────────────────────────────────────
INPUT_FILE="$MPSPDZ_DIR/Player-Data/Input-P0-0"
mkdir -p "$(dirname "$INPUT_FILE")"

python3 /opt/related-work/prepare_data.py \
    --dataset "$DATASET" \
    --output  "$INPUT_FILE" >&2

# Get dimensions: n_train m n_classes
DIMS=$(python3 /opt/related-work/prepare_data.py \
    --dataset "$DATASET" --info-only)
N_TRAIN=$(echo "$DIMS" | awk '{print $1}')
M=$(echo "$DIMS"       | awk '{print $2}')
N_CLASSES=$(echo "$DIMS" | awk '{print $3}')

echo "[data] n_train=$N_TRAIN  m=$M  n_classes=$N_CLASSES"

# ── Copy our MPC program into MP-SPDZ ────────────────────────────────────────
cp /opt/related-work/mpc_programs/${MPC_PROG}.mpc \
   "$MPSPDZ_DIR/Programs/Source/"

# ── Build the compile.py argument list ───────────────────────────────────────
if [[ "$MPC_PROG" == "rf_train" ]]; then
    # rf_train <n_train> <m> <n_levels> <n_trees> <n_classes> [n_threads]
    PROG_ARGS="$N_TRAIN $M $DEPTH $NUM_TREES $N_CLASSES $THREADS"
else
    # dt_train / dt_train_abspoel / dt_train_bhardwaj
    # <n_train> <m> <n_levels> <n_classes> [n_threads]
    PROG_ARGS="$N_TRAIN $M $DEPTH $N_CLASSES $THREADS"
fi

# ── Compile ───────────────────────────────────────────────────────────────────
echo "[compile] ./compile.py -R 64 $MPC_PROG $PROG_ARGS"
cd "$MPSPDZ_DIR"
./compile.py -R 64 $MPC_PROG $PROG_ARGS

# The compiled program name uses hyphens between args
PROG_NAME="${MPC_PROG}-$(echo "$PROG_ARGS" | tr ' ' '-')"
echo "[compile] Compiled → $PROG_NAME"

# ── Run ───────────────────────────────────────────────────────────────────────
echo "[run] Protocol=$PROTOCOL  Program=$PROG_NAME"
START_TIME=$(date +%s%N)

case "$PROTOCOL" in
    ring)
        # 3-party honest-majority with ring (REPLICATED) — matches paper's model
        Scripts/ring.sh "$PROG_NAME"
        ;;
    semi2k)
        # 2-party semi-honest over Z_{2^k} — fast local benchmark
        Scripts/semi2k.sh "$PROG_NAME"
        ;;
    *)
        echo "[ERROR] Unknown protocol: $PROTOCOL (choose ring or semi2k)" >&2
        exit 1
        ;;
esac

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "============================================================"
echo " Wall-clock time: ${ELAPSED_MS} ms"
echo "============================================================"
