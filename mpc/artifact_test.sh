#!/usr/bin/env bash
# =============================================================================
#  ARTIFACT SMOKE TEST — runs one small config to verify the pipeline works.
#  Config: IRIS (n=100, m=4, alpha=9, t=3), depth=4, 3 parties
#  Expected wall-clock: ~30-60 seconds
#
#  Usage:
#    cd ~/PPML-HYBRID-MPC
#    bash artifact_test.sh
# =============================================================================

set -euo pipefail

MP_SPDZ_DIR="${HOME}/PPML-HYBRID-MPC"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

N_PARTIES=3
N=100; M=4; A=9; T_L=3; D=4
EXE="bench_fhe-${N}-${M}-${A}-${T_L}-${D}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# --- SSL certs ---
cd "${MP_SPDZ_DIR}"
if [[ ! -f "Player-Data/P0.pem" ]]; then
  info "Generating SSL certs for ${N_PARTIES} parties..."
  Scripts/setup-ssl.sh "${N_PARTIES}"
fi

# --- Compile ---
info "Compiling ${EXE}..."
./compile.py bench_fhe "$N" "$M" "$A" "$T_L" "$D" 2>&1 | tail -4
success "Compiled."

# --- Run ---
mkdir -p logs
pkill -f sy-shamir-party.x 2>/dev/null || true
sleep 1

info "Launching ${N_PARTIES} parties..."
for i in $(seq 0 $((N_PARTIES-1))); do
  nohup ./sy-shamir-party.x $i "$EXE" -N "$N_PARTIES" \
    > "logs/p${i}-${EXE}-test.log" 2>&1 &
done

while pgrep -f "sy-shamir-party.x" > /dev/null; do
  echo -n "."; sleep 5
done
echo

LOG="logs/p0-${EXE}-test.log"
grep -q "^Time = " "$LOG" || die "No output — check ${LOG}"
success "Run complete."

# --- Results ---
echo
grep -E "^Time|Time[124] =|Data sent|Global" "$LOG"
echo

python3 - "${MP_SPDZ_DIR}" "$N" "$M" "$A" "$T_L" "$D" "${N_PARTIES}" << 'PYEOF'
import math, sys, re, os, glob

MP_SPDZ = sys.argv[1]
N, M, A, T, D = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
N_PARTIES = int(sys.argv[7])
T_TREES = 10
FIELD_BYTES = 16
MB = 1024**2

candidates = glob.glob(os.path.join(MP_SPDZ, "logs", f"p0-bench_fhe-{N}-{M}-{A}-{T}-{D}-test.log"))
txt = open(candidates[0]).read()
def grab(k):
    mo = re.search(rf'^{k} = ([0-9.]+)', txt, re.M)
    return float(mo.group(1)) if mo else None

total = grab('Time'); t1 = grab('Time1'); t2 = grab('Time2'); t4 = grab('Time4')
data  = float(re.search(r'Data sent = ([0-9.]+)', txt).group(1))

ma = A * math.ceil(math.sqrt(M))
nd = 2**D - 1
elems = (2*T_TREES*A*N*M + 4*T_TREES*nd*ma*T*N + T_TREES*nd*N*T + T_TREES*nd*ma*T)
theory = elems * (N_PARTIES-1) * FIELD_BYTES / MB

print(f"{'='*60}")
print(f"  IRIS d=4  |  {N_PARTIES}-party SY-Shamir  |  n={N} m={M} α={A} t={T} ma={ma}")
print(f"{'='*60}")
print(f"  T1 argmax   : {t1:.2f} s")
print(f"  T2 gini     : {t2:.2f} s")
print(f"  T4 integrity: {t4:.2f} s")
print(f"  Total       : {total:.2f} s")
print(f"  Measured P0 : {data:.1f} MB")
print(f"  Theory  P0  : {theory:.1f} MB")
print(f"{'='*60}")
PYEOF
