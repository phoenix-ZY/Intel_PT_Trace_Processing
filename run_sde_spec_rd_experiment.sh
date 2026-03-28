#!/usr/bin/env bash
set -euo pipefail

# Simplified attach-mode pipeline:
# 1) start benchmark process
# 2) attach SDE debugtrace to benchmark pid
# 3) collect for N seconds (or optional icount cap)
# 4) stop benchmark, wait SDE flush, then post-process

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_DIR="${SCRIPT_DIR}/inputs"
INTERMEDIATE_DIR="${SCRIPT_DIR}/intermediate"
OUTPUT_DIR="${SCRIPT_DIR}/outputs"
OUTPUT_MEM_DIR="${OUTPUT_DIR}/mem"
OUTPUT_RD_DIR="${OUTPUT_DIR}/rd"
OUTPUT_REPORT_DIR="${OUTPUT_DIR}/report"

SPEC_ROOT="${HOME}/speccpu2017"
SDE_PATH="${HOME}/ali/sde-external-9.53.0-2025-03-16-lin/sde64"
BENCH_NAME="505.mcf_r"
RUN_ID="run_base_refrate_mytest-m64.0000"
OUT_PREFIX="mcf_attach"
COLLECT_SECONDS=60
COLLECT_INSNS=0
LINE_SIZE=64
SALVAGE_FILL_SEED=1
PROGRESS=0
VERBOSE=0
TRACE_START_TIMEOUT=60

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Core options:
  --out-prefix NAME       output prefix (default: ${OUT_PREFIX})
  --collect-seconds N     attach collection duration in seconds (default: ${COLLECT_SECONDS})
  --collect-insns N       optional icount cap inside SDE (default: ${COLLECT_INSNS}, 0=disabled)

Common options:
  --bench NAME            SPEC bench name (default: ${BENCH_NAME})
  --run-id NAME           SPEC run id directory (default: ${RUN_ID})
  --line-size N           cache line size for RD (default: ${LINE_SIZE})
  --seed N                salvage fill seed (default: ${SALVAGE_FILL_SEED})
  --progress              print trace file size every 5s while collecting
  --verbose               show benchmark/SDE output

Advanced:
  --spec-root DIR         SPEC root (default: ${SPEC_ROOT})
  --sde PATH              SDE path (default: ${SDE_PATH})
  --trace-start-timeout N fail if trace file missing after N seconds (default: ${TRACE_START_TIMEOUT})
  -h, --help              show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-prefix) OUT_PREFIX="$2"; shift 2 ;;
    --collect-seconds) COLLECT_SECONDS="$2"; shift 2 ;;
    --collect-insns) COLLECT_INSNS="$2"; shift 2 ;;
    --bench) BENCH_NAME="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --line-size) LINE_SIZE="$2"; shift 2 ;;
    --seed) SALVAGE_FILL_SEED="$2"; shift 2 ;;
    --progress) PROGRESS=1; shift 1 ;;
    --verbose) VERBOSE=1; shift 1 ;;
    --spec-root) SPEC_ROOT="$2"; shift 2 ;;
    --sde) SDE_PATH="$2"; shift 2 ;;
    --trace-start-timeout) TRACE_START_TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! -x "${SDE_PATH}" ]]; then
  echo "SDE not executable: ${SDE_PATH}" >&2
  exit 2
fi
if [[ "${COLLECT_SECONDS}" -le 0 ]]; then
  echo "--collect-seconds must be > 0" >&2
  exit 2
fi

BENCH_RUN_DIR="${SPEC_ROOT}/benchspec/CPU/${BENCH_NAME}/run/${RUN_ID}"
if [[ ! -d "${BENCH_RUN_DIR}" ]]; then
  echo "Benchmark run dir not found: ${BENCH_RUN_DIR}" >&2
  exit 2
fi

mkdir -p "${INPUT_DIR}" "${INTERMEDIATE_DIR}" "${OUTPUT_MEM_DIR}" "${OUTPUT_RD_DIR}" "${OUTPUT_REPORT_DIR}"
SDE_TRACE="${INPUT_DIR}/${OUT_PREFIX}.sde.slice.txt"
REAL_MEM_JSONL="${OUTPUT_MEM_DIR}/${OUT_PREFIX}.mem.real.jsonl"
INSN_TRACE="${INTERMEDIATE_DIR}/${OUT_PREFIX}.insn.trace.txt"
VIRT_MEM_JSONL="${OUTPUT_MEM_DIR}/${OUT_PREFIX}.mem.virtual.jsonl"
RD_REAL_TXT="${OUTPUT_RD_DIR}/${OUT_PREFIX}.rd.real.txt"
RD_VIRT_TXT="${OUTPUT_RD_DIR}/${OUT_PREFIX}.rd.virtual.txt"
COMPARE_JSON="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.rd.compare.json"
SDE_ATTACH_LOG="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.attach.log"

echo "[1/6] Extract benchmark command..."
if [[ -f "${SPEC_ROOT}/shrc" ]]; then
  # shellcheck disable=SC1090
  source "${SPEC_ROOT}/shrc" >/dev/null 2>&1 || true
fi
SPECINVOKE_BIN="$(command -v specinvoke || true)"
if [[ -z "${SPECINVOKE_BIN}" && -x "${SPEC_ROOT}/bin/specinvoke" ]]; then
  SPECINVOKE_BIN="${SPEC_ROOT}/bin/specinvoke"
fi
if [[ -z "${SPECINVOKE_BIN}" ]]; then
  echo "specinvoke not found in PATH and not found at ${SPEC_ROOT}/bin/specinvoke" >&2
  exit 2
fi
CMD_LINE="$(cd "${BENCH_RUN_DIR}" && "${SPECINVOKE_BIN}" -n | awk '/^\.\.\/run_base/ {print; exit}')"
if [[ -z "${CMD_LINE}" ]]; then
  echo "Failed to extract benchmark command via specinvoke -n" >&2
  exit 2
fi
echo "  command: ${CMD_LINE}"
echo "  debugtrace mode: dt_rawinst"

echo "[2/6] Start benchmark process..."
if [[ "${VERBOSE}" -eq 1 ]]; then
  BENCH_REDIRECT=""
else
  BENCH_REDIRECT="> /dev/null 2>/dev/null"
fi
(
  cd "${BENCH_RUN_DIR}"
  # shellcheck disable=SC2086
  eval "exec ${CMD_LINE} ${BENCH_REDIRECT}"
) &
BENCH_PID=$!
sleep 1
if ! kill -0 "${BENCH_PID}" >/dev/null 2>&1; then
  echo "Benchmark process failed to start." >&2
  exit 2
fi
echo "  benchmark pid: ${BENCH_PID}"

echo "[3/6] Attach SDE debugtrace..."
if [[ "${VERBOSE}" -eq 1 ]]; then
  SDE_REDIRECT="2>&1 | tee \"${SDE_ATTACH_LOG}\""
else
  SDE_REDIRECT="> \"${SDE_ATTACH_LOG}\" 2>&1"
fi

CONTROL_ARG=""
if [[ "${COLLECT_INSNS}" -gt 0 ]]; then
  CONTROL_ARG="-control start:icount:0,stop:icount:${COLLECT_INSNS} -length ${COLLECT_INSNS}"
fi

# shellcheck disable=SC2086
eval "${SDE_PATH} -debugtrace -dt_rawinst 1 -dt_print_tid 1 -dt_out \"${SDE_TRACE}\" ${CONTROL_ARG} -attach-pid ${BENCH_PID} ${SDE_REDIRECT}" &
SDE_PID=$!
echo "  sde pid: ${SDE_PID}"

echo "[4/6] Collect for ${COLLECT_SECONDS}s..."
for ((i=0; i<${COLLECT_SECONDS}; i+=5)); do
  sleep 5
  if [[ "${PROGRESS}" -eq 1 ]]; then
    if [[ -f "${SDE_TRACE}" ]]; then
      sz="$(du -h "${SDE_TRACE}" | awk '{print $1}')"
      echo "[4/6] progress: ${SDE_TRACE} size=${sz}"
    else
      echo "[4/6] progress: waiting for ${SDE_TRACE}"
    fi
  fi
  if [[ ! -d "/proc/${BENCH_PID}" ]]; then
    break
  fi
done

if [[ ! -f "${SDE_TRACE}" ]]; then
  waited=0
  while [[ "${waited}" -lt "${TRACE_START_TIMEOUT}" && ! -f "${SDE_TRACE}" ]]; do
    sleep 1
    waited=$((waited + 1))
  done
fi

echo "  stopping benchmark pid ${BENCH_PID}..."
kill -TERM "${BENCH_PID}" >/dev/null 2>&1 || true
sleep 2
kill -KILL "${BENCH_PID}" >/dev/null 2>&1 || true
wait "${BENCH_PID}" >/dev/null 2>&1 || true

echo "  waiting for sde flush..."
set +e
wait "${SDE_PID}" >/dev/null 2>&1
SDE_EXIT=$?
set -e
if [[ "${SDE_EXIT}" -ne 0 ]]; then
  echo "SDE attach/trace failed with exit code ${SDE_EXIT}" >&2
  echo "See attach log: ${SDE_ATTACH_LOG}" >&2
  exit "${SDE_EXIT}"
fi

if [[ ! -f "${SDE_TRACE}" ]]; then
  echo "Trace file not generated: ${SDE_TRACE}" >&2
  echo "See attach log: ${SDE_ATTACH_LOG}" >&2
  exit 2
fi
echo "  wrote: ${SDE_TRACE}"

echo "[5/6] Convert + recover..."
python3 "${SCRIPT_DIR}/sde_debugtrace_convert.py" -i "${SDE_TRACE}" --mem-out "${REAL_MEM_JSONL}" --insn-out "${INSN_TRACE}"
python3 "${SCRIPT_DIR}/recover_mem_addrs.py" \
  -i "${INSN_TRACE}" \
  -o "${VIRT_MEM_JSONL}" \
  --minimal \
  --init-regs zero \
  --salvage-invalid-mem \
  --salvage-fill-writes \
  --salvage-fill-seed "${SALVAGE_FILL_SEED}" \
  --report-out "${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.recover.skipped.txt"

echo "[6/6] Reuse distance + compare..."
python3 "${SCRIPT_DIR}/reuse_distance.py" -i "${REAL_MEM_JSONL}" --line-size "${LINE_SIZE}" --top 10 --report-out "${RD_REAL_TXT}" >/dev/null
python3 "${SCRIPT_DIR}/reuse_distance.py" -i "${VIRT_MEM_JSONL}" --line-size "${LINE_SIZE}" --top 10 --report-out "${RD_VIRT_TXT}" >/dev/null
python3 "${SCRIPT_DIR}/compare_reuse_profiles.py" --ref "${REAL_MEM_JSONL}" --test "${VIRT_MEM_JSONL}" --access all_streams --line-size "${LINE_SIZE}" --rd-definition stack_depth --json-out "${COMPARE_JSON}" >/dev/null

echo
echo "Done. Outputs:"
echo "  ${SDE_TRACE}"
echo "  ${REAL_MEM_JSONL}"
echo "  ${INSN_TRACE}"
echo "  ${VIRT_MEM_JSONL}"
echo "  ${RD_REAL_TXT}"
echo "  ${RD_VIRT_TXT}"
echo "  ${COMPARE_JSON}"
