#!/usr/bin/env bash
# Build our MP-SPDZ fork (mpc/) with sy-shamir-party.x, with the submodule dependencies pinned to the commits of
# MP-SPDZ v0.4.1 (the version the fork is based on). Used by the Dockerfile and for a manual installation.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build_mpspdz.sh [--march ARCH] [--jobs N] [machines...]

Fetches the dependencies of MP-SPDZ into mpc/deps (pinned commits; mpc/ is not a git submodule, so MP-SPDZ's own
"git submodule update" cannot be used), then runs "make setup" and "make <machines>" in mpc/.
  machines   default: sy-shamir-party.x (Shamir secret sharing with MAC, used for all our MPC experiments)
  --march    value of -march for MP-SPDZ (default: native)
  --jobs     parallel make jobs (default: nproc)
Requirements (Ubuntu 22.04): see README, "Manual installation" (clang, libsodium, libssl, libgmp, Boost >= 1.75).
The prime field size is set in mpc/CONFIG.mine (MOD = -DGFP_MOD_SZ=5, i.e. primes up to 320 bits).
EOF
}

MARCH=native JOBS=$(nproc 2>/dev/null || echo 4) MACHINES=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --march) MARCH=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) MACHINES+=("$1"); shift ;;
  esac
done
[[ ${#MACHINES[@]} -gt 0 ]] || MACHINES=(sy-shamir-party.x)
MPC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../mpc" && pwd)"
cd "$MPC"

fetch() {   # fetch <dir> <url> <commit>
  if [[ -e $1/.git ]] && [[ $(git -C "$1" rev-parse HEAD 2>/dev/null) == "$3" ]]; then return 0; fi
  rm -rf "$1"; mkdir -p "$1"
  git -C "$1" init -q
  git -C "$1" remote add origin "$2"
  git -C "$1" fetch -q --depth 1 origin "$3"
  git -C "$1" checkout -q FETCH_HEAD
}
echo "fetching MP-SPDZ dependencies (pinned to MP-SPDZ v0.4.1) into $MPC/deps"
fetch deps/SimpleOT     https://github.com/mkskeller/SimpleOT                 44aac605389d6478a75b172a9cf6e76e3c964ce7
fetch deps/SimplestOT_C https://github.com/mkskeller/SimplestOT_C             7ef7666909e493a18c99efe56f97cc4d13723005
fetch deps/libOTe       https://github.com/mkskeller/softspoken-implementation 28dab85bba964054dc110701ae3fa9241b292bbd
git -C deps/libOTe submodule update -q --init --recursive
fetch deps/simde        https://github.com/simd-everywhere/simde              0ba20859e9f557cee161d2cab2728b56dca7ec38
fetch deps/sse2neon     https://github.com/DLTcollab/sse2neon                 ddca67108e3e96a288e9aa7e31bfacca2309f624
# the Makefile rule for this one would try "git submodule update" / "git clone" first
[[ -f deps/SimplestOT_C/ref10/Makefile ]] || (cd deps/SimplestOT_C/ref10 && cmake . > /dev/null)

grep -q '^MOD = -DGFP_MOD_SZ=5' CONFIG.mine || echo "MOD = -DGFP_MOD_SZ=5" >> CONFIG.mine
if [[ $MARCH != native ]]; then   # -march=native is the default of mpc/CONFIG
  grep -v '^ARCH = ' CONFIG.mine > CONFIG.mine.tmp || true
  echo "ARCH = -march=$MARCH" >> CONFIG.mine.tmp
  mv CONFIG.mine.tmp CONFIG.mine
fi
echo "CONFIG.mine:"; cat CONFIG.mine

make setup
make -j"$JOBS" "${MACHINES[@]}"
for x in "${MACHINES[@]}"; do
  if ldd "./$x" 2>/dev/null | grep "not found"; then echo "$x: missing shared libraries" >&2; exit 1; fi
done
echo "built: ${MACHINES[*]} in $MPC"
