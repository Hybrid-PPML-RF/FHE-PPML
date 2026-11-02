# shellcheck shell=bash
# Shared settings and helpers of the reproduction scripts. Sourced by scripts/*.sh, not executed.
#
# Paths can be overridden with environment variables (the Docker image sets them):
#   RESULTS_DIR   where logs, tables and the figure go         (default: <repo>/results; Docker: /results)
#   PPML_BIN      the FHE benchmark binary built from main_integrity.cpp (default: <repo>/build/ppml)
#   MPSPDZ_DIR    the MP-SPDZ fork with our MPC programs        (default: <repo>/mpc)
#   BHARDWAJ_DIR  MP-SPDZ fork of Bhardwaj et al. (CCS'24)      (default: /opt/baselines/mp-spdz-bhardwaj)

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd)"
: "${RESULTS_DIR:=$REPO_ROOT/results}"
: "${PPML_BIN:=$REPO_ROOT/build/ppml}"
: "${MPSPDZ_DIR:=$REPO_ROOT/mpc}"
: "${BHARDWAJ_DIR:=/opt/baselines/mp-spdz-bhardwaj}"
DATASETS_CSV="$SCRIPTS_DIR/datasets.csv"

ALL_DATASETS="iris wine cancer digits"
ALL_DEPTHS="4 5 6"
ALL_BINS="0 1"
BIN_ALPHA=8          # number of bins ("8 bins" columns of the paper)

ts()   { date '+%Y-%m-%d %H:%M:%S'; }
info() { echo "[$(ts)] $*" >&2; }
warn() { echo "[$(ts)] WARNING: $*" >&2; }
die()  { echo "[$(ts)] ERROR: $*" >&2; exit 1; }

# "a,b c" -> "a b c"
norm_list() { echo "$*" | tr ',' ' ' | xargs; }

# ds_field <dataset> <id|n|m|alpha|t|label>
ds_field() {
  local ds=$1 col=$2 idx v
  case $col in
    id) idx=2 ;; n) idx=3 ;; m) idx=4 ;; alpha) idx=5 ;; t) idx=6 ;; label) idx=7 ;;
    *) die "ds_field: unknown column '$col'" ;;
  esac
  v=$(awk -F, -v d="$ds" -v i="$idx" '$1 == d { print $i }' "$DATASETS_CSV")
  [[ -n $v ]] || die "unknown dataset '$ds' (known: $ALL_DATASETS)"
  echo "$v"
}

check_list() {   # check_list <what> <allowed values> <values>
  local what=$1 allowed=$2 v
  for v in $3; do
    [[ " $allowed " == *" $v "* ]] || die "invalid $what '$v' (allowed: $allowed)"
  done
}

# Prefix for CPU pinning (--cpus 0-47 emulates the 48 vCPUs per server of the paper on a bigger machine).
cpu_prefix() {
  if [[ -n ${1:-} ]]; then
    command -v taskset >/dev/null || die "--cpus needs taskset (util-linux)"
    echo "taskset -c $1"
  fi
}

# Prefix for a per-run time limit in seconds (0 = none).
timeout_prefix() {
  if [[ ${1:-0} -gt 0 ]]; then echo "timeout --kill-after=60 $1"; fi
}

# (Re)create self-signed certificates for <n> MP-SPDZ parties in <dir> if any is missing or expires within 7 days.
# Certificates must be identical on all hosts of a multi-host run (see README, "Multi-machine WAN setup").
ensure_ssl() {
  local n=$1 dir=$2 i ok=1
  for ((i = 0; i < n; i++)); do
    if [[ ! -f $dir/P$i.pem || ! -f $dir/P$i.key ]] || ! openssl x509 -checkend 604800 -noout -in "$dir/P$i.pem" >/dev/null 2>&1; then
      ok=0
      break
    fi
  done
  if [[ $ok == 0 ]]; then
    info "Generating SSL certificates for $n parties in $dir"
    "$SCRIPTS_DIR/setup_ssl.sh" "$n" "$dir"
  elif ! ls "$dir"/*.0 >/dev/null 2>&1; then
    c_rehash "$dir" >/dev/null 2>&1 || openssl rehash "$dir"
  fi
}

# Write host / build information next to the results (once per stage).
write_run_info() {
  local f=$RESULTS_DIR/run_info.txt
  mkdir -p "$RESULTS_DIR"
  {
    echo "== $(ts) $*"
    echo "host: $(hostname)  nproc: $(nproc 2>/dev/null || echo ?)  mem: $(awk '/MemTotal/ {printf "%.0f GiB", $2/1048576}' /proc/meminfo 2>/dev/null)"
    echo "cpu: $(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +/, "", $2); print $2; exit}')"
    echo "code: ${GIT_COMMIT:-$(git -C "$REPO_ROOT" describe --always --dirty 2>/dev/null || echo unknown)}"
  } >> "$f"
}
