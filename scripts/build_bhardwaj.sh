#!/usr/bin/env bash
# Build the baseline of Bhardwaj et al. (CCS'24): their MP-SPDZ fork, i.e. the head commit of
# https://github.com/data61/MP-SPDZ/pull/1449 (branch master of sandy9999/MP-SPDZ), based on MP-SPDZ 0.4.0.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build_bhardwaj.sh [--dir DIR] [--march ARCH] [--jobs N] [machines...]

Clones the fork at a pinned commit into DIR (default: /opt/baselines/mp-spdz-bhardwaj; set BHARDWAJ_DIR=DIR for
scripts/run_baselines.sh if you choose another one) and builds the protocol binaries.
  machines   default: ps-rep-ring-party.x replicated-ring-party.x
             (3-party replicated secret sharing over Z_2^k; malicious resp. semi-honest, one corruption)
Requires Boost >= 1.75 installed system-wide (README, "Manual installation"): the fork's pinned cryptoTools would
otherwise try to download Boost from a mirror that no longer exists.
USAGE
}

DIR=/opt/baselines/mp-spdz-bhardwaj MARCH=native JOBS=$(nproc 2>/dev/null || echo 4) MACHINES=()
REPO=https://github.com/sandy9999/MP-SPDZ
COMMIT=87d1e5c7850fff6b91de95efb6e62752b5891d7f
while [[ $# -gt 0 ]]; do
  case $1 in
    --dir) DIR=$2; shift 2 ;;
    --march) MARCH=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) MACHINES+=("$1"); shift ;;
  esac
done
[[ ${#MACHINES[@]} -gt 0 ]] || MACHINES=(ps-rep-ring-party.x replicated-ring-party.x)

if [[ $(git -C "$DIR" rev-parse HEAD 2>/dev/null) != "$COMMIT" ]]; then
  mkdir -p "$DIR"
  git -C "$DIR" init -q
  git -C "$DIR" remote add origin "$REPO" 2>/dev/null || git -C "$DIR" remote set-url origin "$REPO"
  git -C "$DIR" fetch -q --depth 1 origin "$COMMIT"
  git -C "$DIR" checkout -q FETCH_HEAD
fi
cd "$DIR"
git submodule update -q --init deps/SimpleOT deps/SimplestOT_C deps/simde deps/sse2neon
git submodule update -q --init --recursive deps/libOTe
if [[ $MARCH != native ]]; then echo "ARCH = -march=$MARCH" >> CONFIG.mine; fi
make setup
make -j"$JOBS" "${MACHINES[@]}"
for x in "${MACHINES[@]}"; do
  if ldd "./$x" 2>/dev/null | grep "not found"; then echo "$x: missing shared libraries" >&2; exit 1; fi
done
[[ -f Programs/Source/bench-dt.mpc ]] || { echo "bench-dt.mpc missing: not the expected fork" >&2; exit 1; }
echo "built: ${MACHINES[*]} in $DIR"
