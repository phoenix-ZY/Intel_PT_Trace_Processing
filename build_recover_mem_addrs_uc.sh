#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/recover_mem_addrs_uc.c"
CORE_SRC="${SCRIPT_DIR}/trace_feature_core.c"
OUT="${SCRIPT_DIR}/recover_mem_addrs_uc"
SDE_SRC="${SCRIPT_DIR}/analyze_sde_trace_uc.c"
SDE_OUT="${SCRIPT_DIR}/analyze_sde_trace_uc"

try_build_with_python_unicorn() {
  local py="${1:-python3}"
  if ! command -v "${py}" >/dev/null 2>&1; then
    return 0
  fi

  local inc lib_so lib_dir pkg_dir
  inc="$("${py}" - <<'PY' 2>/dev/null || true
import os, unicorn
print(os.path.join(os.path.dirname(unicorn.__file__), "include"))
PY
)"
  lib_so="$("${py}" - <<'PY' 2>/dev/null || true
import unicorn.unicorn_py3.unicorn as u
print(u.uclib._name)
PY
)"
  pkg_dir="$("${py}" - <<'PY' 2>/dev/null || true
import os, unicorn
print(os.path.dirname(unicorn.__file__))
PY
)"

  if [[ -n "${lib_so}" && -f "${lib_so}" ]]; then
    lib_dir="$(dirname "${lib_so}")"
  elif [[ -n "${pkg_dir}" && -d "${pkg_dir}/lib" ]]; then
    lib_dir="${pkg_dir}/lib"
  else
    lib_dir=""
  fi

  if [[ -n "${inc}" && -d "${inc}/unicorn" && -n "${lib_dir}" && -d "${lib_dir}" ]]; then
    local so_name=""
    if compgen -G "${lib_dir}/libunicorn.so*" >/dev/null; then
      # Prefer the shared library if present (pip wheels often ship libunicorn.so.2 without a libunicorn.so symlink)
      so_name="$(ls -1 "${lib_dir}"/libunicorn.so* 2>/dev/null | head -n 1 | xargs -n1 basename || true)"
    fi
    if [[ -n "${so_name}" ]] || compgen -G "${lib_dir}/libunicorn.a" >/dev/null; then
      echo "[build] using python unicorn dev files (${py})"
      local unicorn_link="-lunicorn"
      if [[ -n "${so_name}" ]]; then
        unicorn_link="-l:${so_name}"
      fi
      gcc -O3 -march=native -std=c11 -Wall -Wextra \
        -I"${inc}" "${SRC}" "${CORE_SRC}" -o "${OUT}" \
        -L"${lib_dir}" -Wl,-rpath,"${lib_dir}" ${unicorn_link} -pthread -lm
      gcc -O3 -march=native -std=c11 -Wall -Wextra \
        "${SDE_SRC}" "${CORE_SRC}" -o "${SDE_OUT}" -lm
      echo "[build] done: ${OUT}"
      echo "[build] done: ${SDE_OUT}"
      exit 0
    fi
  fi
}

try_build_with_prefix() {
  local prefix="$1"
  local inc="${prefix}/include"
  local lib="${prefix}/lib"

  if [[ -f "${inc}/unicorn/unicorn.h" && -f "${inc}/unicorn/x86.h" ]]; then
    local so_name=""
    if compgen -G "${lib}/libunicorn.so*" >/dev/null; then
      so_name="$(ls -1 "${lib}"/libunicorn.so* 2>/dev/null | head -n 1 | xargs -n1 basename || true)"
    fi
    if [[ -n "${so_name}" ]] || compgen -G "${lib}/libunicorn.a" >/dev/null; then
      echo "[build] using prefix: ${prefix}"
      local unicorn_link="-lunicorn"
      if [[ -n "${so_name}" ]]; then
        unicorn_link="-l:${so_name}"
      fi
      gcc -O3 -march=native -std=c11 -Wall -Wextra \
        -I"${inc}" "${SRC}" "${CORE_SRC}" -o "${OUT}" \
        -L"${lib}" -Wl,-rpath,"${lib}" ${unicorn_link} -pthread -lm
      gcc -O3 -march=native -std=c11 -Wall -Wextra \
        "${SDE_SRC}" "${CORE_SRC}" -o "${SDE_OUT}" -lm
      echo "[build] done: ${OUT}"
      echo "[build] done: ${SDE_OUT}"
      exit 0
    fi
  fi
}

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists unicorn; then
  echo "[build] using pkg-config unicorn"
  gcc -O3 -march=native -std=c11 -Wall -Wextra \
    "${SRC}" "${CORE_SRC}" -o "${OUT}" $(pkg-config --cflags --libs unicorn) -lm
  gcc -O3 -march=native -std=c11 -Wall -Wextra \
    "${SDE_SRC}" "${CORE_SRC}" -o "${SDE_OUT}" -lm
  echo "[build] done: ${OUT}"
  echo "[build] done: ${SDE_OUT}"
  exit 0
fi

try_build_with_python_unicorn python3
try_build_with_python_unicorn python

if [[ -n "${UNICORN_PREFIX:-}" ]]; then
  try_build_with_prefix "${UNICORN_PREFIX}"
fi

if [[ -n "${CONDA_PREFIX:-}" ]]; then
  try_build_with_prefix "${CONDA_PREFIX}"
fi

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  # Kept for backward compatibility, but prefer try_build_with_python_unicorn above.
  try_build_with_python_unicorn python3
  try_build_with_python_unicorn python
fi

echo "[build] could not resolve unicorn dev flags automatically."
echo "Recommended fix (Ubuntu):"
echo "  sudo apt-get update && sudo apt-get install -y libunicorn-dev pkg-config"
echo "Then:"
echo "  bash build_recover_mem_addrs_uc.sh"
echo "Try manually:"
echo "  gcc -O3 -std=c11 -Wall -Wextra -I/path/to/unicorn/include recover_mem_addrs_uc.c trace_feature_core.c -L/path/to/lib -lunicorn -o recover_mem_addrs_uc"
echo "  gcc -O3 -std=c11 -Wall -Wextra analyze_sde_trace_uc.c trace_feature_core.c -o analyze_sde_trace_uc"
exit 2
