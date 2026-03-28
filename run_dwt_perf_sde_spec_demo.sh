#!/usr/bin/env bash
set -euo pipefail

# End-to-end DWT demo pipeline on one SPEC CPU2017 workload:
# - collect a short instruction trace with perf intel_pt
# - collect a short instruction+data trace with Intel SDE debugtrace
# - decode/convert both to canonical insn-trace
# - align PT to SDE (anchor matching)
# - generate synthetic mem traces via Unicorn from PT (and optionally SDE)
# - compare RD/SDP similarity + page hotness, windowed
#
# Defaults are intentionally small (10k insns) to validate the pipeline quickly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_DIR="${SCRIPT_DIR}/inputs"
INTERMEDIATE_DIR="${SCRIPT_DIR}/intermediate"
OUTPUT_DIR="${SCRIPT_DIR}/outputs"
OUTPUT_MEM_DIR="${OUTPUT_DIR}/mem"
OUTPUT_REPORT_DIR="${OUTPUT_DIR}/report"

SPEC_ROOT="${HOME}/speccpu2017"
SDE_PATH="${HOME}/ali/sde-external-9.53.0-2025-03-16-lin/sde64"
BENCH_NAME="505.mcf_r"
RUN_ID="run_base_refrate_mytest-m64.0000"
OUT_PREFIX="dwt_demo"

MAX_INSNS=10000000
# recover_mem_addrs.py: batch JSONL writes (set RECOVER_IO_BATCH_LINES=1 to flush every line for live tail)
RECOVER_IO_BATCH_LINES="${RECOVER_IO_BATCH_LINES:-4096}"
LINE_SIZE=64
ANCHOR_LEN=256
ANCHOR_PT_START=0
SALVAGE_FILL_SEED=1
PT_RECORD_SECONDS=0.005
PT_RETRY_SECONDS=0
ATTACH_DELAY_SECONDS=0
START_STEP=1

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Core:
  --bench NAME            SPEC bench name (default: ${BENCH_NAME})
  --run-id NAME           SPEC run id directory (default: ${RUN_ID})
  --max-insns N           instruction count target (default: ${MAX_INSNS})
  --out-prefix NAME       output prefix (default: ${OUT_PREFIX})

Paths:
  --spec-root DIR         SPEC root (default: ${SPEC_ROOT})
  --sde PATH              Intel SDE path (default: ${SDE_PATH})

Alignment:
  --anchor-len N          anchor instruction length (default: ${ANCHOR_LEN})
  --anchor-pt-start N     starting insn index in PT for anchor (default: ${ANCHOR_PT_START})
  --anchor-sde-start N    alias of --anchor-pt-start (backward compatible)

Other:
  --line-size N           cache line size (default: ${LINE_SIZE})
  --seed N                salvage fill seed for Unicorn (default: ${SALVAGE_FILL_SEED})
  --pt-seconds N          seconds to run perf record (default: ${PT_RECORD_SECONDS})
  --pt-retry-seconds N    optional fallback PT seconds on decode/short-trace failure (default: ${PT_RETRY_SECONDS}, disabled when <=0)
  --attach-delay N        optional delay before perf/SDE attach (default: ${ATTACH_DELAY_SECONDS})
  --pt-attach-delay N     alias of --attach-delay (backward compatible)
  --sde-attach-delay N    alias of --attach-delay (backward compatible)
  --start-step N          start pipeline from step N (1-8, default: ${START_STEP})
  -h, --help              show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bench) BENCH_NAME="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --max-insns) MAX_INSNS="$2"; shift 2 ;;
    --out-prefix) OUT_PREFIX="$2"; shift 2 ;;
    --spec-root) SPEC_ROOT="$2"; shift 2 ;;
    --sde) SDE_PATH="$2"; shift 2 ;;
    --anchor-len) ANCHOR_LEN="$2"; shift 2 ;;
    --anchor-pt-start|--anchor-sde-start) ANCHOR_PT_START="$2"; shift 2 ;;
    --line-size) LINE_SIZE="$2"; shift 2 ;;
    --seed) SALVAGE_FILL_SEED="$2"; shift 2 ;;
    --pt-seconds) PT_RECORD_SECONDS="$2"; shift 2 ;;
    --pt-retry-seconds) PT_RETRY_SECONDS="$2"; shift 2 ;;
    --attach-delay|--pt-attach-delay|--sde-attach-delay) ATTACH_DELAY_SECONDS="$2"; shift 2 ;;
    --start-step) START_STEP="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if ! [[ "${START_STEP}" =~ ^[1-8]$ ]]; then
  echo "--start-step must be an integer in [1, 8], got: ${START_STEP}" >&2
  exit 2
fi

# if awk "BEGIN { exit !(${PT_RECORD_SECONDS} < 1.0) }"; then
#   echo "WARN: --pt-seconds=${PT_RECORD_SECONDS} is too small; bumping to 1.0s for decodable PT output."
#   PT_RECORD_SECONDS=1
# fi

mkdir -p "${INPUT_DIR}" "${INTERMEDIATE_DIR}" "${OUTPUT_MEM_DIR}" "${OUTPUT_REPORT_DIR}"

BENCH_RUN_DIR="${SPEC_ROOT}/benchspec/CPU/${BENCH_NAME}/run/${RUN_ID}"
if [[ ! -d "${BENCH_RUN_DIR}" ]]; then
  echo "Benchmark run dir not found: ${BENCH_RUN_DIR}" >&2
  exit 2
fi
if [[ ! -x "${SDE_PATH}" ]]; then
  echo "SDE not executable: ${SDE_PATH}" >&2
  exit 2
fi
if [[ "${START_STEP}" -le 3 ]] && ! command -v perf >/dev/null 2>&1; then
  echo "perf not found in PATH" >&2
  exit 2
fi

echo "[1/8] Extract SPEC command..."
if [[ -f "${SPEC_ROOT}/shrc" ]]; then
  # shellcheck disable=SC1090
  source "${SPEC_ROOT}/shrc" >/dev/null 2>&1 || true
fi
SPECINVOKE_BIN="$(command -v specinvoke || true)"
if [[ -z "${SPECINVOKE_BIN}" && -x "${SPEC_ROOT}/bin/specinvoke" ]]; then
  SPECINVOKE_BIN="${SPEC_ROOT}/bin/specinvoke"
fi
if [[ -z "${SPECINVOKE_BIN}" ]]; then
  echo "specinvoke not found" >&2
  exit 2
fi
CMD_LINE="$(cd "${BENCH_RUN_DIR}" && "${SPECINVOKE_BIN}" -n | awk '/^\.\.\/run_base/ {print; exit}')"
if [[ -z "${CMD_LINE}" ]]; then
  echo "Failed to extract benchmark command" >&2
  exit 2
fi
echo "  command: ${CMD_LINE}"
CMD_EXE_REL="$(awk '{print $1}' <<< "${CMD_LINE}")"
CMD_EXE_BASENAME="$(basename "${CMD_EXE_REL}")"

cleanup_pid() {
  local pid="${1:-}"
  if [[ -z "${pid}" ]]; then
    return 0
  fi
  if kill -0 "${pid}" >/dev/null 2>&1; then
    kill -TERM "${pid}" >/dev/null 2>&1 || true
    for _ in {1..50}; do
      if ! kill -0 "${pid}" >/dev/null 2>&1; then
        return 0
      fi
      sleep 0.1
    done
    kill -KILL "${pid}" >/dev/null 2>&1 || true
  fi
}

start_spec_background() {
  local stdout_path="$1"
  local stderr_path="$2"
  (
    cd "${BENCH_RUN_DIR}"
    # Use exec so the background shell PID becomes the workload PID.
    # shellcheck disable=SC2086
    bash -c "exec ${CMD_LINE}" >"${stdout_path}" 2>"${stderr_path}" &
    echo $!
  )
}

get_proc_starttime() {
  local pid="$1"
  awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null || true
}

resolve_target_pid() {
  local launcher_pid="$1"
  local expected_exe_basename="$2"
  local timeout_s="${3:-2}"
  local deadline=$((SECONDS + timeout_s))
  local pid exe

  while (( SECONDS <= deadline )); do
    if kill -0 "${launcher_pid}" >/dev/null 2>&1; then
      exe="$(readlink -f "/proc/${launcher_pid}/exe" 2>/dev/null || true)"
      if [[ -n "${exe}" && "$(basename "${exe}")" == "${expected_exe_basename}" ]]; then
        echo "${launcher_pid}"
        return 0
      fi

      while IFS= read -r pid; do
        [[ -z "${pid}" ]] && continue
        exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [[ -n "${exe}" && "$(basename "${exe}")" == "${expected_exe_basename}" ]]; then
          echo "${pid}"
          return 0
        fi
      done < <(pgrep -P "${launcher_pid}" || true)
    fi
    sleep 0.02
  done

  echo "${launcher_pid}"
  return 0
}

collect_pt_with_perf() {
  local record_seconds="$1"

  PT_SPEC_STDOUT="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.spec.stdout.txt"
  PT_SPEC_STDERR="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.spec.stderr.txt"
  PT_LAUNCHER_PID="$(start_spec_background "${PT_SPEC_STDOUT}" "${PT_SPEC_STDERR}")"
  PT_TARGET_PID="$(resolve_target_pid "${PT_LAUNCHER_PID}" "${CMD_EXE_BASENAME}" 3)"
  trap 'cleanup_pid "${PT_LAUNCHER_PID}"; [[ "${PT_TARGET_PID}" != "${PT_LAUNCHER_PID}" ]] && cleanup_pid "${PT_TARGET_PID}"' EXIT
  if ! kill -0 "${PT_TARGET_PID}" >/dev/null 2>&1; then
    echo "Failed to start SPEC workload for PT collection (launcher pid=${PT_LAUNCHER_PID}, target pid=${PT_TARGET_PID})." >&2
    return 2
  fi
  echo "  PT target pid: ${PT_TARGET_PID}"
  PT_TARGET_EXE="$(readlink -f "/proc/${PT_TARGET_PID}/exe" 2>/dev/null || true)"
  if [[ -n "${PT_TARGET_EXE}" ]]; then
    echo "  PT target exe: ${PT_TARGET_EXE}"
  fi
  if [[ -r "/proc/${PT_TARGET_PID}/cmdline" ]]; then
    PT_CMDLINE="$(tr '\0' ' ' < "/proc/${PT_TARGET_PID}/cmdline" || true)"
    echo "  PT target cmdline: ${PT_CMDLINE}"
  fi

  if awk "BEGIN { exit !(${ATTACH_DELAY_SECONDS} > 0) }"; then
    sleep "${ATTACH_DELAY_SECONDS}"
  fi

  if ! kill -0 "${PT_TARGET_PID}" >/dev/null 2>&1; then
    echo "SPEC workload exited before perf could attach (pid=${PT_TARGET_PID})." >&2
    echo "Try --attach-delay 0 and increase --pt-seconds." >&2
    return 2
  fi

  # NOTE: intel_pt support depends on CPU/kernel/perf permissions.
  # This records user-space only (//u). Some environments may require sudo or perf_event_paranoid tweaks.
  # IMPORTANT: Prefer a graceful end so perf can finalize perf.data properly.
  set +e
  perf record -q -e intel_pt//u -o "${PT_DATA}" -p "${PT_TARGET_PID}" -- sleep "${record_seconds}" \
    >/dev/null 2>"${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.record.stderr.txt"
  PERF_RECORD_EXIT=$?
  set -e
  cleanup_pid "${PT_LAUNCHER_PID}"
  if [[ "${PT_TARGET_PID}" != "${PT_LAUNCHER_PID}" ]]; then
    cleanup_pid "${PT_TARGET_PID}"
  fi
  trap - EXIT

  if [[ "${PERF_RECORD_EXIT}" -ne 0 ]]; then
    echo "perf record failed (exit ${PERF_RECORD_EXIT})." >&2
    echo "See: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.record.stderr.txt" >&2
    return 2
  fi
  if [[ ! -s "${PT_DATA}" ]]; then
    echo "perf record did not produce perf.data (empty or missing): ${PT_DATA}" >&2
    echo "See: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.record.stderr.txt" >&2
    echo "Common causes: no intel_pt support, permissions, perf_event_paranoid, or need sudo." >&2
    return 2
  fi
  return 0
}

decode_pt_to_insn() {
  set +e
  perf script --insn-trace -F tid,time,ip,insn -i "${PT_DATA}" > "${PT_SCRIPT_RAW}" 2> "${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.script.stderr.txt"
  PT_SCRIPT_EXIT=$?
  set -e
  if [[ "${PT_SCRIPT_EXIT}" -ne 0 ]]; then
    echo "perf script --insn-trace failed (exit ${PT_SCRIPT_EXIT})." >&2
    echo "See: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.script.stderr.txt" >&2
    echo "If PT collection used timeout, try a larger --pt-seconds (>= 2) so perf can flush." >&2
    return 2
  fi
  python3 "${SCRIPT_DIR}/perf_insntrace_convert.py" -i "${PT_SCRIPT_RAW}" -o "${PT_INSN_TRACE}" >/dev/null
  return 0
}

PT_DATA="${INTERMEDIATE_DIR}/${OUT_PREFIX}.pt.perf.data"
PT_SCRIPT_RAW="${INTERMEDIATE_DIR}/${OUT_PREFIX}.pt.perf.script.txt"
PT_INSN_TRACE="${INTERMEDIATE_DIR}/${OUT_PREFIX}.pt.insn.trace.txt"

SDE_TRACE="${INPUT_DIR}/${OUT_PREFIX}.sde.debugtrace.txt"
SDE_MEM_REAL="${OUTPUT_MEM_DIR}/${OUT_PREFIX}.sde.mem.real.jsonl"
SDE_INSN_TRACE="${INTERMEDIATE_DIR}/${OUT_PREFIX}.sde.insn.trace.txt"
SDE_STDOUT_LOG="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stdout.txt"
SDE_PS_BEFORE="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.ps.before.txt"
SDE_PS_AFTER="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.ps.after.txt"
SDE_PROC_STATUS_BEFORE="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.proc.status.before.txt"
SDE_PROC_STATUS_AFTER="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.proc.status.after.txt"

DWT_MEM_VIRT="${OUTPUT_MEM_DIR}/${OUT_PREFIX}.pt.mem.virtual.jsonl"

ALIGN_OFFSET_TXT="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt_minus_sde.offset.txt"
WINDOWED_JSON="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.windowed.json"
COMPARE_JSON="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.rd.compare.json"

if [[ "${START_STEP}" -le 2 ]]; then
  echo "[2/8] Collect PT with perf (intel_pt)..."
  echo "  output: ${PT_DATA}"
  collect_pt_with_perf "${PT_RECORD_SECONDS}"
else
  echo "[2/8] Skipped (reuse existing PT outputs; start-step=${START_STEP})"
fi

if [[ "${START_STEP}" -le 3 ]]; then
  echo "[3/8] Decode PT to instruction stream..."
  if ! decode_pt_to_insn; then
    if [[ "${START_STEP}" -le 2 ]] && awk "BEGIN { exit !(${PT_RETRY_SECONDS} > 0) }"; then
      echo "  PT decode failed; retrying PT collection with --pt-retry-seconds=${PT_RETRY_SECONDS} ..."
      collect_pt_with_perf "${PT_RETRY_SECONDS}"
      decode_pt_to_insn
    else
      exit 2
    fi
  fi
else
  echo "[3/8] Skipped (reuse existing ${PT_INSN_TRACE}; start-step=${START_STEP})"
fi

echo "[4/8] Slice PT insn trace to first ${MAX_INSNS} instructions..."
if [[ ! -f "${PT_INSN_TRACE}" ]]; then
  echo "PT insn trace not found for step [4/8]: ${PT_INSN_TRACE}" >&2
  echo "Run from --start-step 2/3 first, or provide an existing PT insn trace." >&2
  exit 2
fi
head -n "${MAX_INSNS}" "${PT_INSN_TRACE}" > "${PT_INSN_TRACE}.slice"
mv "${PT_INSN_TRACE}.slice" "${PT_INSN_TRACE}"
PT_LINES="$(wc -l < "${PT_INSN_TRACE}" || echo 0)"
if [[ "${PT_LINES}" -lt "${ANCHOR_LEN}" ]]; then
  if [[ "${START_STEP}" -le 2 ]] && awk "BEGIN { exit !(${PT_RETRY_SECONDS} > 0) }"; then
    echo "  PT insn trace too short (${PT_LINES} < ${ANCHOR_LEN}); retrying with --pt-retry-seconds=${PT_RETRY_SECONDS} ..."
    collect_pt_with_perf "${PT_RETRY_SECONDS}"
    decode_pt_to_insn
    head -n "${MAX_INSNS}" "${PT_INSN_TRACE}" > "${PT_INSN_TRACE}.slice"
    mv "${PT_INSN_TRACE}.slice" "${PT_INSN_TRACE}"
    PT_LINES="$(wc -l < "${PT_INSN_TRACE}" || echo 0)"
  fi
fi
if [[ "${PT_LINES}" -lt "${ANCHOR_LEN}" ]]; then
  echo "PT insn trace too short for alignment: lines=${PT_LINES}, need >= ${ANCHOR_LEN}" >&2
  echo "See raw perf script: ${PT_SCRIPT_RAW}" >&2
  echo "Tip: increase --pt-seconds (e.g. 3-10), and check perf stderr logs:" >&2
  echo "  ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.record.stderr.txt" >&2
  echo "  ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.pt.perf.script.stderr.txt" >&2
  exit 2
fi

echo "[5/8] Collect SDE debugtrace (icount=${MAX_INSNS})..."
SDE_SPEC_STDOUT="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.spec.stdout.txt"
SDE_SPEC_STDERR="${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.spec.stderr.txt"
SDE_LAUNCHER_PID="$(start_spec_background "${SDE_SPEC_STDOUT}" "${SDE_SPEC_STDERR}")"
SDE_TARGET_PID="$(resolve_target_pid "${SDE_LAUNCHER_PID}" "${CMD_EXE_BASENAME}" 3)"
trap 'cleanup_pid "${SDE_LAUNCHER_PID}"; [[ "${SDE_TARGET_PID}" != "${SDE_LAUNCHER_PID}" ]] && cleanup_pid "${SDE_TARGET_PID}"' EXIT
if ! kill -0 "${SDE_TARGET_PID}" >/dev/null 2>&1; then
  echo "Failed to start SPEC workload for SDE collection (launcher pid=${SDE_LAUNCHER_PID}, target pid=${SDE_TARGET_PID})." >&2
  exit 2
fi
echo "  SDE target pid: ${SDE_TARGET_PID}"
SDE_TARGET_STARTTIME_BEFORE="$(get_proc_starttime "${SDE_TARGET_PID}")"
echo "  SDE target starttime(before attach): ${SDE_TARGET_STARTTIME_BEFORE:-unknown}"
SDE_TARGET_EXE="$(readlink -f "/proc/${SDE_TARGET_PID}/exe" 2>/dev/null || true)"
if [[ -n "${SDE_TARGET_EXE}" ]]; then
  echo "  SDE target exe: ${SDE_TARGET_EXE}"
fi
if [[ -r "/proc/${SDE_TARGET_PID}/cmdline" ]]; then
  SDE_CMDLINE="$(tr '\0' ' ' < "/proc/${SDE_TARGET_PID}/cmdline" || true)"
  echo "  SDE target cmdline: ${SDE_CMDLINE}"
fi
ps -p "${SDE_TARGET_PID}" -o pid,ppid,stat,etime,lstart,cmd > "${SDE_PS_BEFORE}" 2>/dev/null || true
cp "/proc/${SDE_TARGET_PID}/status" "${SDE_PROC_STATUS_BEFORE}" 2>/dev/null || true
echo "  SDE pre-attach ps snapshot: ${SDE_PS_BEFORE}"
echo "  SDE pre-attach proc status: ${SDE_PROC_STATUS_BEFORE}"

if awk "BEGIN { exit !(${ATTACH_DELAY_SECONDS} > 0) }"; then
  sleep "${ATTACH_DELAY_SECONDS}"
fi

if ! kill -0 "${SDE_TARGET_PID}" >/dev/null 2>&1; then
  echo "SPEC workload exited before SDE could attach (pid=${SDE_TARGET_PID})." >&2
  echo "Try --attach-delay 0 or use a longer-running workload/input." >&2
  exit 2
fi

echo "  SDE attach cmd:"
echo "    ${SDE_PATH} -attach-pid ${SDE_TARGET_PID} -debugtrace -dt_rawinst 1 -dt_print_tid 1 -dt_out ${SDE_TRACE} -control start:icount:0,stop:icount:${MAX_INSNS} -length ${MAX_INSNS}"

# Attach SDE to the running process, and stop after MAX_INSNS (from attach point).
set +e
"${SDE_PATH}" -attach-pid "${SDE_TARGET_PID}" -debugtrace -dt_rawinst 1 -dt_print_tid 1 -dt_out "${SDE_TRACE}" \
  -control start:icount:0,stop:icount:${MAX_INSNS} -length "${MAX_INSNS}" \
  >"${SDE_STDOUT_LOG}" 2>"${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stderr.txt"
SDE_EXIT=$?
set -e
ps -p "${SDE_TARGET_PID}" -o pid,ppid,stat,etime,lstart,cmd > "${SDE_PS_AFTER}" 2>/dev/null || true
cp "/proc/${SDE_TARGET_PID}/status" "${SDE_PROC_STATUS_AFTER}" 2>/dev/null || true
echo "  SDE post-attach ps snapshot: ${SDE_PS_AFTER}"
echo "  SDE post-attach proc status: ${SDE_PROC_STATUS_AFTER}"
if [[ -s "${SDE_STDOUT_LOG}" ]]; then
  echo "  SDE stdout log: ${SDE_STDOUT_LOG}"
fi
if [[ -s "${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stderr.txt" ]]; then
  echo "  SDE stderr log: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stderr.txt"
fi
SDE_TARGET_STARTTIME_AFTER="$(get_proc_starttime "${SDE_TARGET_PID}")"
if [[ -n "${SDE_TARGET_STARTTIME_BEFORE}" && -n "${SDE_TARGET_STARTTIME_AFTER}" && "${SDE_TARGET_STARTTIME_BEFORE}" != "${SDE_TARGET_STARTTIME_AFTER}" ]]; then
  echo "WARN: target PID starttime changed during attach (possible PID reuse)." >&2
  echo "  before=${SDE_TARGET_STARTTIME_BEFORE}, after=${SDE_TARGET_STARTTIME_AFTER}" >&2
fi

if [[ "${SDE_EXIT}" -ne 0 ]]; then
  cleanup_pid "${SDE_LAUNCHER_PID}"
  if [[ "${SDE_TARGET_PID}" != "${SDE_LAUNCHER_PID}" ]]; then
    cleanup_pid "${SDE_TARGET_PID}"
  fi
  trap - EXIT
  echo "SDE debugtrace failed (exit ${SDE_EXIT})." >&2
  echo "See SDE stderr: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stderr.txt" >&2
  exit 2
fi
if [[ ! -f "${SDE_TRACE}" ]]; then
  cleanup_pid "${SDE_LAUNCHER_PID}"
  if [[ "${SDE_TARGET_PID}" != "${SDE_LAUNCHER_PID}" ]]; then
    cleanup_pid "${SDE_TARGET_PID}"
  fi
  trap - EXIT
  echo "SDE trace not generated: ${SDE_TRACE}" >&2
  exit 2
fi

# SDE may return before all buffered trace output lands on disk.
# Wait briefly for trace file size to stabilize to avoid under-counting and early kill.
last_size=-1
for _ in {1..20}; do
  cur_size="$(wc -c < "${SDE_TRACE}" 2>/dev/null || echo 0)"
  if [[ "${cur_size}" -eq "${last_size}" && "${cur_size}" -gt 0 ]]; then
    break
  fi
  last_size="${cur_size}"
  sleep 0.1
done

python3 "${SCRIPT_DIR}/sde_debugtrace_convert.py" -i "${SDE_TRACE}" --mem-out "${SDE_MEM_REAL}" --insn-out "${SDE_INSN_TRACE}" >/dev/null
SDE_LINES="$(wc -l < "${SDE_INSN_TRACE}" || echo 0)"
echo "  SDE collected insn lines: ${SDE_LINES} (target=${MAX_INSNS})"
if [[ "${SDE_LINES}" -lt "${MAX_INSNS}" ]]; then
  echo "WARN: SDE lines (${SDE_LINES}) below target (${MAX_INSNS}); avoiding immediate kill to reduce early truncation risk." >&2
  sleep 0.5
fi
cleanup_pid "${SDE_LAUNCHER_PID}"
if [[ "${SDE_TARGET_PID}" != "${SDE_LAUNCHER_PID}" ]]; then
  cleanup_pid "${SDE_TARGET_PID}"
fi
trap - EXIT
if [[ "${SDE_LINES}" -lt "${ANCHOR_LEN}" ]]; then
  echo "SDE insn trace too short for alignment: lines=${SDE_LINES}, need >= ${ANCHOR_LEN}" >&2
  echo "See SDE stderr: ${OUTPUT_REPORT_DIR}/${OUT_PREFIX}.sde.stderr.txt" >&2
  exit 2
fi
if [[ ! -s "${SDE_MEM_REAL}" ]]; then
  echo "SDE real mem JSONL is empty: ${SDE_MEM_REAL}" >&2
  exit 2
fi

echo "[6/8] Align PT insns to SDE insns (anchor match)..."
PT_MINUS_SDE_OFFSET="$(python3 "${SCRIPT_DIR}/align_insn_traces.py" \
  --pt "${PT_INSN_TRACE}" \
  --sde "${SDE_INSN_TRACE}" \
  --mode pt-in-sde \
  --anchor-len "${ANCHOR_LEN}" \
  --pt-start "${ANCHOR_PT_START}" \
  --anchor-len-list "256,128,64,32" \
  --pt-start-list "0,256,1024,4096,8192,16384" \
  --ignore-ip)"
echo "${PT_MINUS_SDE_OFFSET}" > "${ALIGN_OFFSET_TXT}"
echo "  offset(pt_start - sde_start) = ${PT_MINUS_SDE_OFFSET}"

echo "[7/8] Generate DWT synthetic mem trace from PT via Unicorn..."
python3 "${SCRIPT_DIR}/recover_mem_addrs.py" \
  -i "${PT_INSN_TRACE}" \
  -o "${DWT_MEM_VIRT}" \
  --minimal \
  --init-regs zero \
  --salvage-invalid-mem \
  --salvage-fill-writes \
  --salvage-fill-seed "${SALVAGE_FILL_SEED}" \
  --max-insns "${MAX_INSNS}" \
  --io-batch-lines "${RECOVER_IO_BATCH_LINES}" \
  >/dev/null
if [[ ! -s "${DWT_MEM_VIRT}" ]]; then
  echo "DWT virtual mem JSONL is empty: ${DWT_MEM_VIRT}" >&2
  exit 2
fi

echo "[8/8] Compare RD profiles + windowed DWT metrics..."
python3 "${SCRIPT_DIR}/compare_reuse_profiles.py" \
  --ref "${SDE_MEM_REAL}" \
  --test "${DWT_MEM_VIRT}" \
  --access all_streams \
  --line-size "${LINE_SIZE}" \
  --rd-definition stack_depth \
  --json-out "${COMPARE_JSON}" \
  >/dev/null

# Windowed: use small window equal to MAX_INSNS for the demo.
python3 "${SCRIPT_DIR}/windowed_compare.py" \
  --ref "${SDE_MEM_REAL}" \
  --test "${DWT_MEM_VIRT}" \
  --access all \
  --line-size "${LINE_SIZE}" \
  --window-insns "${MAX_INSNS}" \
  --ref-insn-idx-offset 0 \
  --test-insn-idx-offset "${PT_MINUS_SDE_OFFSET}" \
  --json-out "${WINDOWED_JSON}" \
  >/dev/null

echo
echo "Done. Key outputs:"
echo "  PT insn trace:        ${PT_INSN_TRACE}"
echo "  SDE insn trace:       ${SDE_INSN_TRACE}"
echo "  SDE real mem:         ${SDE_MEM_REAL}"
echo "  DWT mem (PT->Unicorn):${DWT_MEM_VIRT}"
echo "  Align offset:         ${ALIGN_OFFSET_TXT}"
echo "  RD compare JSON:      ${COMPARE_JSON}"
echo "  Windowed JSON:        ${WINDOWED_JSON}"

