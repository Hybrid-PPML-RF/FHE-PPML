#!/usr/bin/env bash
# Generate the self-signed certificates MP-SPDZ uses for its secure channels.
# Same as mpc/Scripts/setup-ssl.sh, but valid for 10 years instead of OpenSSL's default of 30 days
# (the certificates committed in mpc/Player-Data expired in July 2026).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/setup_ssl.sh <n_parties> [dir] [days]

Creates dir/P<i>.pem and dir/P<i>.key for i = 0..n_parties-1 (CN=P<i>) and the hash links MP-SPDZ needs.
  dir   default: $MPSPDZ_DIR/Player-Data (mpc/Player-Data)
  days  validity, default 3650

For a run on several machines, all machines need the SAME files: generate them once and copy the
directory to every machine (or use one Docker image for all machines), see README.
EOF
}
[[ ${1:-} == -h || ${1:-} == --help || $# -lt 1 ]] && { usage; exit 0; }

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
n=$1
dir=${2:-$MPSPDZ_DIR/Player-Data}
days=${3:-3650}
mkdir -p "$dir"
for ((i = 0; i < n; i++)); do
  openssl req -newkey rsa:2048 -nodes -x509 -days "$days" -subj "/CN=P$i" \
    -out "$dir/P$i.pem" -keyout "$dir/P$i.key" 2>/dev/null
done
rm -f "$dir"/*.0
c_rehash "$dir" >/dev/null 2>&1 || openssl rehash "$dir"
echo "SSL certificates for $n parties in $dir (valid $days days)"
