#!/usr/bin/env bash
# Entry point of the Docker image.
#   docker run IMAGE [reproduce_all.sh options]     -> scripts/reproduce_all.sh (default: everything)
#   docker run IMAGE run_fhe.sh|run_mpc.sh|run_baselines.sh|make_results.py|wan_emulation.sh|setup_ssl.sh [options]
#   docker run -it IMAGE bash                        -> a shell (repository in /opt/FHE-PPML)
set -e
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
case ${1:-} in
  run_fhe.sh|run_mpc.sh|run_baselines.sh|wan_emulation.sh|setup_ssl.sh|reproduce_all.sh|launch_multihost.sh)
    cmd=$1; shift; exec "$SCRIPTS/$cmd" "$@" ;;
  make_results.py)
    shift; exec python3 "$SCRIPTS/make_results.py" "$@" ;;
  ""|-*)
    exec "$SCRIPTS/reproduce_all.sh" "$@" ;;
  *)
    exec "$@" ;;
esac
