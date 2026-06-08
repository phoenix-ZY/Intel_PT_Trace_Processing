#!/usr/bin/env bash
# Source canonical Docker image tags from colocation-bench-suite.
#
# Usage:
#   source scripts/env/source_cbs_images.sh
#   # or
#   CBS_ROOT=/path/to/colocation-bench-suite source scripts/source_cbs_images.sh

_intel_pt_repo_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")/../.." && pwd)"
  printf '%s' "${here}"
}

CBS_ROOT="${CBS_ROOT:-${COLOCATION_BENCH_SUITE_DIR:-}}"
if [[ -z "${CBS_ROOT}" ]]; then
  CBS_ROOT="/home/huangtianhao/colocation-bench-suite"
fi

IMAGES_ENV="${CBS_ROOT}/conf/images.env"
if [[ ! -f "${IMAGES_ENV}" ]]; then
  echo "[WARN] CBS images env not found: ${IMAGES_ENV}" >&2
  return 0 2>/dev/null || exit 0
fi

# shellcheck source=/dev/null
source "${IMAGES_ENV}"

export COLOCATION_BENCH_SUITE_DIR="${COLOCATION_BENCH_SUITE_DIR:-${CBS_ROOT}}"
export CLAB_IMAGE="${CLAB_IMAGE:-${CBS_OFFLINE_IMAGE}}"
export DCPERF_V2_IMAGE="${DCPERF_V2_IMAGE:-${CBS_DCPERF_V2_IMAGE}}"
export TAO_CLAB_IMAGE="${TAO_CLAB_IMAGE:-${CBS_DCPERF_V2_IMAGE}}"
export DOCKER_BENCH_CLIENT_IMAGE="${DOCKER_BENCH_CLIENT_IMAGE:-${CBS_BENCH_CLIENT_IMAGE}}"
