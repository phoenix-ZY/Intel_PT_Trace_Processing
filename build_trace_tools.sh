#!/usr/bin/env bash
# Build trace_feature_processor (Intel PT) and analyze_sde_trace_uc (SDE validation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C_SRC_DIR="${SCRIPT_DIR}/csrc"
CORE_SRC="${C_SRC_DIR}/trace_feature_core.c"
PROCESSOR_SRC="${C_SRC_DIR}/trace_feature_processor.c"
PROCESSOR_OUT="${SCRIPT_DIR}/trace_feature_processor"
SDE_SRC="${C_SRC_DIR}/analyze_sde_trace_uc.c"
SDE_OUT="${SCRIPT_DIR}/analyze_sde_trace_uc"

resolve_xed_prefix() {
  if [[ -n "${XED_PREFIX:-}" ]]; then
    printf '%s\n' "${XED_PREFIX}"
    return
  fi

  local candidate
  for candidate in \
    "${HOME}/xed/obj/wkit" \
    "${HOME}/ali/xed/obj/wkit" \
    "/flash/huangtianhao/xed/obj/wkit" \
    "/usr/local"; do
    if [[ -f "${candidate}/include/xed/xed-interface.h" ]] && compgen -G "${candidate}/lib/libxed.*" >/dev/null; then
      printf '%s\n' "${candidate}"
      return
    fi
  done

  printf '%s\n' "/flash/huangtianhao/xed/obj/wkit"
}

XED_PREFIX="$(resolve_xed_prefix)"

build_sde_analyzer() {
  gcc -O3 -march=native -std=c11 -Wall -Wextra \
    "${SDE_SRC}" "${CORE_SRC}" -o "${SDE_OUT}" -lm
  echo "[build] done: ${SDE_OUT}"
}

build_trace_feature_processor_if_xed() {
  local unicorn_inc="$1"
  shift

  if [[ ! -f "${XED_PREFIX}/include/xed/xed-interface.h" ]]; then
    echo "[build] skip ${PROCESSOR_OUT}: missing XED headers under ${XED_PREFIX} (set XED_PREFIX to build it)" >&2
    return 0
  fi
  if ! compgen -G "${XED_PREFIX}/lib/libxed.*" >/dev/null; then
    echo "[build] skip ${PROCESSOR_OUT}: missing libxed under ${XED_PREFIX}/lib (set XED_PREFIX to build it)" >&2
    return 0
  fi

  local inc_args=()
  if [[ -n "${unicorn_inc}" ]]; then
    inc_args+=("-I${unicorn_inc}")
  fi

  gcc -O3 -march=native -std=c11 -Wall -Wextra \
    "${inc_args[@]}" -I"${XED_PREFIX}/include" "${PROCESSOR_SRC}" "${CORE_SRC}" -o "${PROCESSOR_OUT}" \
    "$@" \
    -L"${XED_PREFIX}/lib" -Wl,-rpath,"${XED_PREFIX}/lib" -lxed -pthread -lm
  echo "[build] done: ${PROCESSOR_OUT}"
}

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
      so_name="$(ls -1 "${lib_dir}"/libunicorn.so* 2>/dev/null | head -n 1 | xargs -n1 basename || true)"
    fi
    if [[ -n "${so_name}" ]] || compgen -G "${lib_dir}/libunicorn.a" >/dev/null; then
      echo "[build] using python unicorn dev files (${py})"
      local unicorn_link="-lunicorn"
      if [[ -n "${so_name}" ]]; then
        unicorn_link="-l:${so_name}"
      fi
      build_trace_feature_processor_if_xed \
        "${inc}" \
        -L"${lib_dir}" -Wl,-rpath,"${lib_dir}" ${unicorn_link}
      build_sde_analyzer
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
      build_trace_feature_processor_if_xed \
        "${inc}" \
        -L"${lib}" -Wl,-rpath,"${lib}" ${unicorn_link}
      build_sde_analyzer
      exit 0
    fi
  fi
}

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists unicorn; then
  echo "[build] using pkg-config unicorn"
  build_trace_feature_processor_if_xed "" $(pkg-config --cflags --libs unicorn)
  build_sde_analyzer
  exit 0
fi

try_build_with_python_unicorn python3
try_build_with_python_unicorn python
if [[ -x "/home/huangtianhao/anaconda3/envs/intel_PT/bin/python" ]]; then
  try_build_with_python_unicorn /home/huangtianhao/anaconda3/envs/intel_PT/bin/python
fi
if [[ -x "/flash/huangtianhao/venv_py39/bin/python" ]]; then
  try_build_with_python_unicorn /flash/huangtianhao/venv_py39/bin/python
fi

if [[ -n "${UNICORN_PREFIX:-}" ]]; then
  try_build_with_prefix "${UNICORN_PREFIX}"
fi

if [[ -n "${CONDA_PREFIX:-}" ]]; then
  try_build_with_prefix "${CONDA_PREFIX}"
fi

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  try_build_with_python_unicorn python3
  try_build_with_python_unicorn python
fi

echo "[build] could not resolve unicorn dev flags automatically."
echo "Recommended fix (Ubuntu):"
echo "  sudo apt-get update && sudo apt-get install -y libunicorn-dev pkg-config"
echo "Then:"
echo "  bash build_trace_tools.sh"
echo "Manual build examples:"
echo "  gcc -O3 -std=c11 -Wall -Wextra -I/path/to/unicorn/include -I\${XED_PREFIX}/include \\"
echo "    csrc/trace_feature_processor.c csrc/trace_feature_core.c -o trace_feature_processor \\"
echo "    -L/path/to/lib -L\${XED_PREFIX}/lib -lunicorn -lxed -pthread -lm"
echo "  gcc -O3 -std=c11 -Wall -Wextra csrc/analyze_sde_trace_uc.c csrc/trace_feature_core.c -o analyze_sde_trace_uc -lm"
exit 2
