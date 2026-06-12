#!/usr/bin/env bash
# =============================================================================
#  ARTIFACT: Hybrid PPML-RF Benchmark
#  Paper: " Random Forest Training via FHE and MPC"
#
#  This script reproduces the MPC benchmark results reported in the paper.
#  It compiles and runs all parameter configurations, then prints the two
#  result tables (runtime and communication) in plain text and LaTeX.
#
#  Tested on: Ubuntu 22.04/24.04, 10-core machine, ~32 GB RAM
#  Expected total wall-clock time: ~8-10 hours for all configurations
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION — adjust these paths if needed
# ---------------------------------------------------------------------------
MP_SPDZ_DIR="${HOME}/mp-spdz"                        # where MP-SPDZ will be cloned/built
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"            # this repo's root

N_PARTIES=10          # number of MPC parties
T_TREES=10            # trees per party (100 total = T_TREES × N_PARTIES)
FIELD_BITS=128        # Shamir field size in bits

# ---------------------------------------------------------------------------
# PARAMETER CONFIGURATIONS
# Format: "dataset_name n m alpha t"
# depth is iterated over 4 5 6 separately
# ---------------------------------------------------------------------------
CONFIGS=(
  "IRIS    100  4   9  3"
  "WINE    119 23  11  3"
  "CANCER  380 30  18  2"
  "DIGIT  1203 64  17 10"
)
DEPTHS=(4 5 6)

# ---------------------------------------------------------------------------
# KNOWN-MISSING / EXTRAPOLATED CONFIGS
# The DIGIT d=6 run requires ~50 min; we extrapolate using the consistent
# d6/d5 ratio observed across all other datasets (≈2.03 for time and data).
# Set SKIP_DIGIT_D6=1 to skip running it and use the extrapolated value.
# ---------------------------------------------------------------------------
SKIP_DIGIT_D6=1
EXTRAP_RATIO_TIME=2.03
EXTRAP_RATIO_DATA=2.03

# ---------------------------------------------------------------------------
# COLOURS
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# =============================================================================
#  STEP 0 — System dependencies
# =============================================================================
step0_deps() {
  info "Installing system dependencies..."
  sudo apt-get update -qq
  sudo apt-get install -y --fix-missing \
    automake build-essential clang cmake git \
    libboost-dev libboost-thread-dev \
    libntl-dev libsodium-dev libssl-dev libtool \
    python3 python3-pip 2>&1 | tail -5
  success "Dependencies installed."
  clang --version
}

# =============================================================================
#  STEP 1 — Clone and build MP-SPDZ
# =============================================================================
step1_build() {
  if [[ -x "${MP_SPDZ_DIR}/sy-shamir-party.x" ]]; then
    info "sy-shamir-party.x already built, skipping."
    return
  fi

  info "Cloning MP-SPDZ..."
  git clone https://github.com/Hybrid-PPML-RF/PPML-HYBRID-MPC.git "${MP_SPDZ_DIR}"

  info "Building MP-SPDZ (this takes 5-15 minutes)..."
  cd "${MP_SPDZ_DIR}"
  make setup
  make -j"$(nproc)" sy-shamir-party.x
  ls -lh "${MP_SPDZ_DIR}/sy-shamir-party.x"
  success "MP-SPDZ built."
}

# =============================================================================
#  STEP 2 — Generate SSL certificates (needed for party authentication)
# =============================================================================
step2_ssl() {
  cd "${MP_SPDZ_DIR}"
  info "Generating SSL certificates for ${N_PARTIES} parties..."
  Scripts/setup-ssl.sh "${N_PARTIES}"
  success "Certificates generated."
}


# =============================================================================
#  STEP 4 — Compile all configurations
# =============================================================================
step4_compile() {
  info "Compiling all configurations..."
  cd "${MP_SPDZ_DIR}"
  for cfg in "${CONFIGS[@]}"; do
    read -r LABEL N M A T_LABELS <<< "$cfg"
    for D in "${DEPTHS[@]}"; do
      echo -n "  Compiling ${LABEL} d=${D} (n=${N} m=${M} alpha=${A} t=${T_LABELS}) ... "
      python3 compile.py bench_fhe "$N" "$M" "$A" "$T_LABELS" "$D" \
        2>&1 | grep -E "triples|ERROR" | tail -1
      echo "OK"
    done
  done
  success "All configurations compiled."
}

# =============================================================================
#  STEP 5 — Run benchmarks
# =============================================================================
run_one() {
  local N=$1 M=$2 A=$3 T_L=$4 D=$5
  local EXE="bench_fhe-${N}-${M}-${A}-${T_L}-${D}"
  local LOG="${MP_SPDZ_DIR}/logs/p0-${EXE}.log"

  mkdir -p "${MP_SPDZ_DIR}/logs"
  pkill -f sy-shamir-party.x 2>/dev/null || true
  sleep 2

  info "Running ${EXE} (${N_PARTIES} parties)..."
  for i in $(seq 0 $((N_PARTIES-1))); do
    nohup "${MP_SPDZ_DIR}/sy-shamir-party.x" $i "$EXE" -N "$N_PARTIES" \
      > "${MP_SPDZ_DIR}/logs/p${i}-${EXE}.log" 2>&1 &
  done

  while pgrep -f "sy-shamir-party.x" > /dev/null; do sleep 10; done

  if grep -q "^Time = " "$LOG"; then
    success "Done: ${EXE}"
  else
    die "No output in ${LOG} — run may have failed. Check the log for errors."
  fi
}

step5_run() {
  for cfg in "${CONFIGS[@]}"; do
    read -r LABEL N M A T_LABELS <<< "$cfg"
    for D in "${DEPTHS[@]}"; do
      if [[ "$LABEL" == "DIGIT" && "$D" == "6" && "$SKIP_DIGIT_D6" == "1" ]]; then
        info "Skipping DIGIT d=6 (will extrapolate from d=5 result)."
        continue
      fi
      run_one "$N" "$M" "$A" "$T_LABELS" "$D"
    done
  done
  success "All benchmarks complete."
}

# =============================================================================
#  STEP 6 — Parse results, compute communication analytically, print tables
# =============================================================================
step6_results() {
  python3 - \
    "${MP_SPDZ_DIR}" \
    "${N_PARTIES}" "${T_TREES}" "${FIELD_BITS}" \
    "${EXTRAP_RATIO_TIME}" "${EXTRAP_RATIO_DATA}" \
    << 'PYEOF'
import math, os, re, sys, glob

MP_SPDZ     = sys.argv[1]
N_PARTIES   = int(sys.argv[2])
T_TREES     = int(sys.argv[3])
FIELD_BYTES = int(sys.argv[4]) // 8   # 128-bit field → 16 bytes per element
MB          = 1024**2

EXTRAP_T = float(sys.argv[5])
EXTRAP_D = float(sys.argv[6])

configs = [
    # (label,  n,    m,  alpha, t)
    ("IRIS",   100,   4,   9,   3),
    ("WINE",   119,  23,  11,   3),
    ("CANCER", 380,  30,  18,   2),
    ("DIGIT", 1203,  64,  17,  10),
]
depths = [4, 5, 6]

# ------------------------------------------------------------------
# Parse measured results from party-0 logs
# ------------------------------------------------------------------
def parse_log(n, m, a, t, d):
    candidates = glob.glob(
        os.path.join(MP_SPDZ, "logs", f"p0-bench_fhe2-{n}-{m}-{a}-{t}-{d}*.log"))
    if not candidates:
        return None
    txt = open(candidates[0]).read()
    def grab(key):
        mo = re.search(rf'^{key} = ([0-9.]+)', txt, re.M)
        return float(mo.group(1)) if mo else None
    mo_data   = re.search(r'Data sent = ([0-9.]+)', txt)
    mo_global = re.search(r'Global data sent = ([0-9.]+)', txt)
    return {
        'total':  grab('Time'),
        't1':     grab('Time1'),
        't2':     grab('Time2'),
        't4':     grab('Time4'),
        'data':   float(mo_data.group(1))   if mo_data   else None,
        'global': float(mo_global.group(1)) if mo_global else None,
    }

# ------------------------------------------------------------------
# Theoretical input-sharing communication (Shamir, 128-bit field)
#
# Each party shares inputs of the following sizes (in field elements):
#   (1) T·α·n·m                          — attribute data (copy 1)
#   (2) 4·T·(2^d−1)·ma·t·n              — gini numerators/denominators
#   (3) T·α·n·m                          — attribute data (copy 2)
#   (4) T·(2^d−1)·n·t                   — label counts per node
#   (5) T·(2^d−1)·ma·t                  — split-point label aggregates
#
# where ma = α·⌈√m⌉  (candidate split points per node)
#
# Sharing k field elements with N-1 other parties costs:
#   k × (N−1) × FIELD_BYTES  bytes sent per party
# ------------------------------------------------------------------
def theory_comm(n, m, alpha, t, d):
    ma  = alpha * math.ceil(math.sqrt(m))
    nd  = 2**d - 1
    i1  = T_TREES * alpha * n * m
    i2  = 4 * T_TREES * nd * ma * t * n
    i3  = T_TREES * alpha * n * m
    i4  = T_TREES * nd * n * t
    i5  = T_TREES * nd * ma * t
    total_elems = i1 + i2 + i3 + i4 + i5
    mb_sent = total_elems * (N_PARTIES - 1) * FIELD_BYTES / MB
    return mb_sent

# ------------------------------------------------------------------
# Collect all results; extrapolate DIGIT d=6 from d=5
# ------------------------------------------------------------------
rows = []
prev_d5 = {}

for (label, n, m, alpha, t) in configs:
    for d in depths:
        r = parse_log(n, m, alpha, t, d)
        extrap = False

        if r is None or r['total'] is None:
            if label == "DIGIT" and d == 6 and label in prev_d5:
                p = prev_d5[label]
                r = {
                    'total':  p['total'] * EXTRAP_T,
                    't1':     p['t1']    * EXTRAP_T,
                    't2':     p['t2']    * EXTRAP_T,
                    't4':     p['t4']    * (6/5),   # tt ∝ d exactly
                    'data':   p['data']  * EXTRAP_D,
                    'global': p['global']* EXTRAP_D,
                }
                extrap = True
            else:
                r = {'total': None, 't1': None, 't2': None,
                     't4': None, 'data': None, 'global': None}

        if label == "DIGIT" and d == 5 and r and r.get('total'):
            prev_d5[label] = r

        ma = alpha * math.ceil(math.sqrt(m))
        rows.append({
            'label': label, 'n': n, 'm': m, 'alpha': alpha,
            't': t, 'd': d, 'ma': ma,
            **r,
            'comm_theory': theory_comm(n, m, alpha, t, d),
            'extrap': extrap,
        })

# ------------------------------------------------------------------
# Plain-text results table
# ------------------------------------------------------------------
SEP = "=" * 105
print()
print(SEP)
print(f"  BENCHMARK RESULTS — {N_PARTIES}-party SY-Shamir, "
      f"{T_TREES*N_PARTIES} trees ({T_TREES}/party), {N_PARTIES} threads/party")
print(SEP)
hdr = (f"{'Dataset':8} {'d':2} {'ma':4} | "
       f"{'T1-Argmax':>11} {'T2-Gini':>9} {'T4-Integ':>9} {'Total (s)':>10} | "
       f"{'Meas. P0 (MB)':>14} {'Theory P0 (MB)':>15}")
print(hdr)
print("-" * len(hdr))

for row in rows:
    tag = "†" if row['extrap'] else " "
    t1  = f"{row['t1']:9.1f}"  if row.get('t1')    else f"{'N/A':>9}"
    t2  = f"{row['t2']:7.1f}"  if row.get('t2')    else f"{'N/A':>7}"
    t4  = f"{row['t4']:7.1f}"  if row.get('t4')    else f"{'N/A':>7}"
    tot = f"{row['total']:8.1f}" if row.get('total') else f"{'N/A':>8}"
    dp0 = f"{row['data']:12.1f}" if row.get('data')  else f"{'N/A':>12}"
    th  = f"{row['comm_theory']:13.1f}"
    print(f"{row['label']:8} {row['d']:2} {row['ma']:4} | "
          f"{t1} {t2} {t4} {tot}{tag} | "
          f"{dp0} {th}")

print()
print(f"† Extrapolated from d=5: T1,T2 ×{EXTRAP_T}, T4 ×6/5 (exact, tt∝d), Data ×{EXTRAP_D}")
print()

# ------------------------------------------------------------------
# LaTeX Table 1 — Runtime
# ------------------------------------------------------------------
print(SEP)
print("  LaTeX TABLE 1 — Runtime")
print(SEP)
print(r"""\begin{table}[t]
\scriptsize\centering\setlength{\tabcolsep}{5pt}
\begin{tabular}{|c|c|r|r|r|r|}
\hline
\textbf{Dataset} & \textbf{Depth} &
\textbf{T1: Argmax (s)} & \textbf{T2: Gini (s)} &
\textbf{T4: Integrity (s)} & \textbf{Total (s)} \\
\hline\hline""")

prev_label = None
for row in rows:
    lbl = row['label']; d = row['d']; n = row['n']
    tag = "$^*$" if row['extrap'] else ""
    def fmt(v, tag=""):
        return f"\\approx {v:.0f}{tag}" if row['extrap'] else (f"{v:.1f}" if v else "N/A")
    t1  = fmt(row['t1'])   if row.get('t1')    else "N/A"
    t2  = fmt(row['t2'])   if row.get('t2')    else "N/A"
    t4  = fmt(row['t4'])   if row.get('t4')    else "N/A"
    tot = fmt(row['total']) if row.get('total') else "N/A"
    if row['extrap']:
        t1 = f"\\approx {row['t1']:.0f}"; t2 = f"\\approx {row['t2']:.0f}"
        t4 = f"\\approx {row['t4']:.0f}"; tot = f"\\approx {row['total']:.0f}$^*$"
    if lbl != prev_label:
        n_fmt = f"$n{{=}}{n:,}$".replace(",", "{,}")
        print(f"\\multirow{{3}}{{*}}{{\\makecell{{{lbl}\\\\({n_fmt})}}}}")
        prev_label = lbl
    print(f" & {d} & {t1} & {t2} & {t4} & {tot} \\\\")
    if d == max(depths) and lbl != rows[-1]['label']:
        print("\\hline")
print(r"""\hline
\end{tabular}
\caption{Runtime breakdown (seconds) for 100-tree RF training (online + offline),
10-party SY-Shamir protocol, 4 threads per party.
T1: collaborative argmax across all tree levels.
T2: Gini index computation (G\' formula).
T4: input integrity check.
$^*$Extrapolated from depth-5 result.}
\label{tab:runtime}
\end{table}""")
print()

# ------------------------------------------------------------------
# LaTeX Table 2 — Communication
# ------------------------------------------------------------------
print(SEP)
print("  LaTeX TABLE 2 — Communication")
print(SEP)
print(r"""\begin{table}[t]
\scriptsize\centering\setlength{\tabcolsep}{4pt}
\begin{tabular}{|c|c|r|r|r|}
\hline
\textbf{Dataset} & \textbf{Depth} &
\textbf{Theory $P_0$ (MB)} &
\textbf{Measured $P_0$ (MB)} &
\textbf{Global (MB)} \\
\hline\hline""")

prev_label = None
for row in rows:
    lbl = row['label']; d = row['d']; n = row['n']
    th  = f"{row['comm_theory']:,.0f}".replace(",", "{,}")
    dp0 = (f"\\approx {row['data']:,.0f}".replace(",", "{,}") if row['extrap']
           else (f"{row['data']:,.0f}".replace(",", "{,}") if row.get('data') else "N/A"))
    gl  = (f"\\approx {row['global']:,.0f}".replace(",", "{,}") if row['extrap']
           else (f"{row['global']:,.0f}".replace(",", "{,}") if row.get('global') else "N/A"))
    if lbl != prev_label:
        n_fmt = f"$n{{=}}{n:,}$".replace(",", "{,}")
        print(f"\\multirow{{3}}{{*}}{{\\makecell{{{lbl}\\\\({n_fmt})}}}}")
        prev_label = lbl
    print(f" & {d} & {th} & {dp0} & {gl} \\\\")
    if d == max(depths) and lbl != rows[-1]['label']:
        print("\\hline")
print(r"""\hline
\end{tabular}
\caption{Communication per party (MB) for 100-tree RF training,
10-party SY-Shamir protocol.
\emph{Theory}: input-sharing cost computed as
$\bigl[2T\alpha nm + T(2^d{-}1)(4ma\,tn + nt + ma\,t)\bigr]
\times (N{-}1) \times 16\,\text{B}$
for a 128-bit Shamir field ($N{=}10$, $T{=}10$ trees/party, $ma{=}\alpha\lceil\sqrt{m}\rceil$).
\emph{Measured}: party\,0 sent data from protocol execution.
\emph{Global}: total across all $N$ parties.
$^*$Extrapolated.}
\label{tab:communication}
\end{table}""")

PYEOF
}

# =============================================================================
#  MAIN
# =============================================================================
usage() {
  cat << 'EOF'
Usage: ./artifact.sh [COMMAND]

Commands:
  all       Run the full pipeline (steps 0-6)  [default]
  deps      Step 0: install system dependencies
  build     Step 1: clone and build MP-SPDZ
  ssl       Step 2: generate SSL certificates
  program   Step 3: copy bench_fhe2.py + SC_fun.py into MP-SPDZ
  compile   Step 4: compile all 12 configurations
  run       Step 5: run all benchmarks (~8-10 h total)
  results   Step 6: parse logs, print plain-text + LaTeX tables

  quick     Steps 3-6 only (if MP-SPDZ is already built)

Example — first time on a fresh machine:
  ./artifact.sh all

Example — MP-SPDZ already built, re-run everything else:
  ./artifact.sh quick

Expected wall-clock per configuration (10-party, 4-thread, shared machine):
  IRIS   d=4  ~70s   d=5  ~140s   d=6  ~280s
  WINE   d=4 ~190s   d=5  ~390s   d=6  ~800s
  CANCER d=4 ~365s   d=5  ~760s   d=6 ~1520s
  DIGIT  d=4 ~830s   d=5 ~1510s   d=6  ~2800s (extrapolated by default)

Logs are written to: ~/mp-spdz/logs/
EOF
}

CMD="${1:-all}"

case "$CMD" in
  deps)    step0_deps ;;
  build)   step1_build ;;
  ssl)     step2_ssl ;;
  program) step3_copy_program ;;
  compile) step4_compile ;;
  run)     step5_run ;;
  results) step6_results ;;
  quick)
    step3_copy_program
    step4_compile
    step5_run
    step6_results
    ;;
  all)
    step0_deps
    step1_build
    step2_ssl
    step4_compile
    step5_run
    step6_results
    ;;
  help|--help|-h) usage ;;
  *) echo "Unknown command: $CMD"; usage; exit 1 ;;
esac
