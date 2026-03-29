#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/recover_mem_addrs_uc.c"
OUT="${SCRIPT_DIR}/recover_mem_addrs_uc"

if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists unicorn; then
  echo "[build] using pkg-config unicorn"
  gcc -O3 -march=native -std=c11 -Wall -Wextra \
    "${SRC}" -o "${OUT}" $(pkg-config --cflags --libs unicorn) -lm
  echo "[build] done: ${OUT}"
  exit 0
fi

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  INC="${VIRTUAL_ENV}/lib/python3.10/site-packages/unicorn/include"
  if [[ -d "${INC}" ]]; then
    LIB_SO="$(python3 -c "import unicorn.unicorn_py3.unicorn as u; print(u.uclib._name)" 2>/dev/null || true)"
    if [[ -n "${LIB_SO}" && -f "${LIB_SO}" ]]; then
      LIB_DIR="$(dirname "${LIB_SO}")"
      echo "[build] pkg-config not found, using venv unicorn paths"
      gcc -O3 -march=native -std=c11 -Wall -Wextra \
        -I"${INC}" "${SRC}" -o "${OUT}" \
        -L"${LIB_DIR}" -Wl,-rpath,"${LIB_DIR}" -lunicorn -lm
      echo "[build] done: ${OUT}"
      exit 0
    fi
  fi
fi

echo "[build] could not resolve unicorn dev flags automatically."
echo "Try manually:"
echo "  gcc -O3 -std=c11 -Wall -Wextra -I/path/to/unicorn/include recover_mem_addrs_uc.c -L/path/to/lib -lunicorn -o recover_mem_addrs_uc"
exit 2
