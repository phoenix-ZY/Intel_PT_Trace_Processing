#define _GNU_SOURCE

/* Unicorn recovery helpers (hook_mem, maps, salvage, parse_trace_line, ...). */
#include "recover_mem_addrs_uc.c"

#include <xed/xed-interface.h>

#include <math.h>
#include <unistd.h>

typedef struct {
    uint64_t decoded;
    uint64_t decode_errors;
    uint64_t categories[XED_CATEGORY_LAST];
    uint64_t iclasses[XED_ICLASS_LAST];
    uint64_t branches;
    uint64_t cond_branches;
    uint64_t uncond_branches;
    uint64_t indirect_branches;
    uint64_t calls;
    uint64_t direct_calls;
    uint64_t indirect_calls;
    uint64_t returns;
    uint64_t syscalls;
    uint64_t operand_mix[16];
    uint64_t branch_known;
    uint64_t branch_taken;
    uint64_t branch_not_taken;
    uint64_t branch_unknown_next_ip;
    uint64_t cond_branch_known;
    uint64_t cond_branch_taken;
    uint64_t cond_branch_not_taken;
    uint64_t cond_branch_unknown_next_ip;
    uint64_t cond_branch_pattern_window;
    uint64_t cond_branch_pattern_len;
    U64Map branch_site_taken;
    U64Map branch_site_not_taken;
    U64Map branch_site_last_outcome;
    U64Map branch_site_transitions;
    U64Map branch_pattern4;
    U64Map branch_pattern8;
    U64Map branch_pattern16;
    U64Map branch_pattern32;
    U64Map gpr_last_read;
    U64Map gpr_last_write;
    U64Map vec_last_read;
    U64Map vec_last_write;
    uint64_t dep_count[6];
    uint64_t dep_sum[6];
    uint64_t dep_buckets[6][5];
    uint64_t ipc_lines;
    uint64_t ipc_value_count;
    double ipc_value_sum;
    uint64_t ipc_retire_count;
    uint64_t ipc_retire_num_sum;
    uint64_t ipc_retire_den_sum;
} PortraitStats;

typedef enum {
    OPMIX_REG_TO_REG = 0,
    OPMIX_REG_TO_MEM = 1,
    OPMIX_MEM_TO_REG = 2,
    OPMIX_MEM_TO_MEM = 3,
    OPMIX_IMM_TO_REG = 4,
    OPMIX_IMM_TO_MEM = 5,
    OPMIX_REG = 6,
    OPMIX_MEM = 7,
    OPMIX_IMM = 8,
    OPMIX_NONE = 9,
    OPMIX_OTHER = 10,
    OPMIX_COUNT = 11,
} OpMixKind;

typedef enum {
    OP_KIND_NONE = 0,
    OP_KIND_REG = 1,
    OP_KIND_MEM = 2,
    OP_KIND_IMM = 3,
    OP_KIND_OTHER = 4,
} OperandKind;

typedef enum {
    DEP_GPR_RAW = 0,
    DEP_GPR_WAW = 1,
    DEP_GPR_WAR = 2,
    DEP_VEC_RAW = 3,
    DEP_VEC_WAW = 4,
    DEP_VEC_WAR = 5,
    DEP_KIND_COUNT = 6,
} DepKind;

typedef struct {
    const char *out_path;
    const char *mem_out_path;
    uint64_t max_insns;
    uint64_t progress_every;
    uint64_t analysis_line_size;
    uint64_t analysis_sdp_max_lines;
    uint64_t analysis_rd_hist_cap_lines;
    uint64_t analysis_stride_bin_cap_lines;
    bool analysis_stack_depth;
    bool split_crossline;
    bool mvs_enable;
    bool fast_exit;
    bool salvage_invalid_mem;
    bool salvage_reads;
    int seed;
    uint64_t rcx_soft_threshold;
    uint64_t code_base;
    uint64_t code_size;
    uint64_t stack_base;
    uint64_t stack_size;
    uint64_t page_size;
} ProcessorOpts;

static void processor_usage(const char *prog) {
    fprintf(
        stderr,
        "Usage: perf script -f --insn-trace -F tid,cpu,time,ip,insn,ipc ... | %s --out features.json [options]\n"
        "Options:\n"
        "  --out PATH                         combined feature JSON output\n"
        "  --mem-out PATH                     optional recovered memory JSONL output\n"
        "  --max-insns N                      stop after N executed instructions\n"
        "  --progress-every N                 print progress every N instructions\n"
        "  --analysis-line-size N             locality line size, default 64\n"
        "  --analysis-sdp-max-lines N         locality SDP cap, default 262144\n"
        "  --analysis-rd-definition MODE      stack_depth|distinct_since_last\n"
        "  --analysis-rd-hist-cap-lines N     RD histogram cap, default 262144\n"
        "  --analysis-stride-bin-cap-lines N  stride bin cap, default 262144\n"
        "  --split-crossline on|off           split cross-line memory accesses, default on\n"
        "  --mvs on|off                       synthetic memory value stream seeding, default on\n"
        "  --fast-exit on|off                 let the OS reclaim Unicorn state, default on\n"
        "  --salvage-invalid-mem              salvage memory operands for invalid Unicorn insns\n"
        "  --salvage-reads                    include read salvage with --salvage-invalid-mem\n"
        "  --seed N                           deterministic seed, default 1\n"
        "  --rcx-soft-threshold N             REP RCX soft threshold, default 128\n"
        "  --code-base N --code-size N        synthetic code region\n"
        "  --stack-base N --stack-size N      synthetic stack region\n"
        "  --page-size N                      page size, default 4096\n",
        prog
    );
}

static bool portrait_is_branch_category(xed_category_enum_t category) {
    return category == XED_CATEGORY_COND_BR ||
           category == XED_CATEGORY_UNCOND_BR ||
           category == XED_CATEGORY_CALL ||
           category == XED_CATEGORY_RET;
}

static bool portrait_action_reads(const xed_operand_t *op) {
    xed_operand_action_enum_t rw = xed_operand_rw(op);
    return xed_operand_action_read(rw) || xed_operand_action_conditional_read(rw);
}

static bool portrait_action_writes(const xed_operand_t *op) {
    xed_operand_action_enum_t rw = xed_operand_rw(op);
    return xed_operand_action_written(rw) || xed_operand_action_conditional_write(rw);
}

static bool portrait_is_gpr(xed_reg_enum_t reg) {
    xed_reg_class_enum_t cls = xed_reg_class(reg);
    return cls == XED_REG_CLASS_GPR ||
           cls == XED_REG_CLASS_GPR8 ||
           cls == XED_REG_CLASS_GPR16 ||
           cls == XED_REG_CLASS_GPR32 ||
           cls == XED_REG_CLASS_GPR64;
}

static bool portrait_is_vec(xed_reg_enum_t reg) {
    xed_reg_class_enum_t cls = xed_reg_class(reg);
    return cls == XED_REG_CLASS_XMM ||
           cls == XED_REG_CLASS_YMM ||
           cls == XED_REG_CLASS_ZMM ||
           cls == XED_REG_CLASS_MASK;
}

static xed_reg_enum_t portrait_normalize_reg(xed_reg_enum_t reg) {
    if (reg == XED_REG_INVALID) return reg;
    return xed_get_largest_enclosing_register(reg);
}

static uint64_t portrait_reg_key(uint32_t tid, xed_reg_enum_t reg) {
    return (((uint64_t)tid) << 32) ^ (uint64_t)reg;
}

static int portrait_dep_bucket(uint64_t d) {
    if (d == 0) return 0;
    if (d <= 4) return 1;
    if (d <= 16) return 2;
    if (d <= 64) return 3;
    return 4;
}

static void portrait_dep_add(PortraitStats *stats, DepKind kind, uint64_t d) {
    if (!stats || kind >= DEP_KIND_COUNT) return;
    stats->dep_count[kind]++;
    stats->dep_sum[kind] += d;
    stats->dep_buckets[kind][portrait_dep_bucket(d)]++;
}

static void portrait_track_reg_deps(
    PortraitStats *stats,
    uint32_t tid,
    xed_reg_enum_t reg,
    bool reads,
    bool writes,
    uint64_t insn_idx
) {
    if (!stats || reg == XED_REG_INVALID) return;
    xed_reg_enum_t nr = portrait_normalize_reg(reg);
    if (nr == XED_REG_INVALID) return;
    bool is_gpr = portrait_is_gpr(nr);
    bool is_vec = portrait_is_vec(nr);
    if (!is_gpr && !is_vec) return;

    U64Map *last_read = is_gpr ? &stats->gpr_last_read : &stats->vec_last_read;
    U64Map *last_write = is_gpr ? &stats->gpr_last_write : &stats->vec_last_write;
    DepKind raw_kind = is_gpr ? DEP_GPR_RAW : DEP_VEC_RAW;
    DepKind waw_kind = is_gpr ? DEP_GPR_WAW : DEP_VEC_WAW;
    DepKind war_kind = is_gpr ? DEP_GPR_WAR : DEP_VEC_WAR;
    uint64_t key = portrait_reg_key(tid, nr);
    uint64_t last = 0;

    if (reads && map_get(last_write, key, &last) && insn_idx >= last) {
        portrait_dep_add(stats, raw_kind, insn_idx - last);
    }
    if (writes && map_get(last_write, key, &last) && insn_idx >= last) {
        portrait_dep_add(stats, waw_kind, insn_idx - last);
    }
    if (writes && map_get(last_read, key, &last) && insn_idx >= last) {
        portrait_dep_add(stats, war_kind, insn_idx - last);
    }
}

static void portrait_commit_reg_access(
    PortraitStats *stats,
    uint32_t tid,
    xed_reg_enum_t reg,
    bool reads,
    bool writes,
    uint64_t insn_idx
) {
    if (!stats || reg == XED_REG_INVALID) return;
    xed_reg_enum_t nr = portrait_normalize_reg(reg);
    if (nr == XED_REG_INVALID) return;
    bool is_gpr = portrait_is_gpr(nr);
    bool is_vec = portrait_is_vec(nr);
    if (!is_gpr && !is_vec) return;
    uint64_t key = portrait_reg_key(tid, nr);
    if (reads) map_put(is_gpr ? &stats->gpr_last_read : &stats->vec_last_read, key, insn_idx);
    if (writes) map_put(is_gpr ? &stats->gpr_last_write : &stats->vec_last_write, key, insn_idx);
}

static OperandKind portrait_operand_kind_from_name(xed_operand_enum_t name) {
    if (name == XED_OPERAND_MEM0 || name == XED_OPERAND_MEM1 || name == XED_OPERAND_AGEN) return OP_KIND_MEM;
    if (name == XED_OPERAND_IMM0 || name == XED_OPERAND_IMM1 || name == XED_OPERAND_UIMM0 ||
        name == XED_OPERAND_UIMM1 || name == XED_OPERAND_PTR || name == XED_OPERAND_RELBR) return OP_KIND_IMM;
    if (xed_operand_is_register(name)) return OP_KIND_REG;
    return OP_KIND_OTHER;
}

static OpMixKind portrait_pair_opmix_kind(OperandKind src, OperandKind dst) {
    if (src == OP_KIND_REG && dst == OP_KIND_REG) return OPMIX_REG_TO_REG;
    if (src == OP_KIND_REG && dst == OP_KIND_MEM) return OPMIX_REG_TO_MEM;
    if (src == OP_KIND_MEM && dst == OP_KIND_REG) return OPMIX_MEM_TO_REG;
    if (src == OP_KIND_MEM && dst == OP_KIND_MEM) return OPMIX_MEM_TO_MEM;
    if (src == OP_KIND_IMM && dst == OP_KIND_REG) return OPMIX_IMM_TO_REG;
    if (src == OP_KIND_IMM && dst == OP_KIND_MEM) return OPMIX_IMM_TO_MEM;
    return OPMIX_OTHER;
}

static OpMixKind portrait_single_opmix_kind(OperandKind k) {
    if (k == OP_KIND_REG) return OPMIX_REG;
    if (k == OP_KIND_MEM) return OPMIX_MEM;
    if (k == OP_KIND_IMM) return OPMIX_IMM;
    if (k == OP_KIND_NONE) return OPMIX_NONE;
    return OPMIX_OTHER;
}

static uint64_t portrait_branch_target(const TraceInsn *insn, const xed_decoded_inst_t *decoded_inst) {
    unsigned int width = xed_decoded_inst_get_branch_displacement_width(decoded_inst);
    if (!insn || width == 0) return 0;
    int64_t disp = xed_decoded_inst_get_branch_displacement(decoded_inst);
    return (uint64_t)((int64_t)(insn->ip + insn->code_len) + disp);
}

static void portrait_add_cond_branch_pattern(PortraitStats *stats, bool taken) {
    if (!stats) return;
    stats->cond_branch_pattern_window = ((stats->cond_branch_pattern_window << 1) | (taken ? 1ULL : 0ULL));
    if (stats->cond_branch_pattern_len < 32) stats->cond_branch_pattern_len++;
    const unsigned int lens[4] = {4, 8, 16, 32};
    U64Map *maps[4] = {
        &stats->branch_pattern4,
        &stats->branch_pattern8,
        &stats->branch_pattern16,
        &stats->branch_pattern32,
    };
    for (unsigned int i = 0; i < 4; i++) {
        unsigned int len = lens[i];
        if (stats->cond_branch_pattern_len < len) continue;
        uint64_t mask = (len == 64) ? UINT64_MAX : ((1ULL << len) - 1ULL);
        uint64_t key = stats->cond_branch_pattern_window & mask;
        uint64_t cur = 0;
        if (!map_get(maps[i], key, &cur)) cur = 0;
        map_put(maps[i], key, cur + 1);
    }
}

static void portrait_add_branch_outcome(
    PortraitStats *stats,
    const TraceInsn *insn,
    const TraceInsn *next,
    uint64_t target,
    bool is_conditional
) {
    if (!stats || !insn || target == 0) return;
    uint64_t site = mix64((((uint64_t)insn->tid) << 32) ^ insn->ip);
    if (!next || next->tid != insn->tid) {
        stats->branch_unknown_next_ip++;
        if (is_conditional) stats->cond_branch_unknown_next_ip++;
        return;
    }
    bool taken = next->ip == target;
    stats->branch_known++;
    if (taken) stats->branch_taken++;
    else stats->branch_not_taken++;
    if (is_conditional) {
        stats->cond_branch_known++;
        if (taken) stats->cond_branch_taken++;
        else stats->cond_branch_not_taken++;
        portrait_add_cond_branch_pattern(stats, taken);
    }

    U64Map *site_map = taken ? &stats->branch_site_taken : &stats->branch_site_not_taken;
    uint64_t cur = 0;
    if (!map_get(site_map, site, &cur)) cur = 0;
    map_put(site_map, site, cur + 1);

    uint64_t last = 0;
    if (map_get(&stats->branch_site_last_outcome, site, &last) && last != (uint64_t)taken) {
        uint64_t tr = 0;
        if (!map_get(&stats->branch_site_transitions, site, &tr)) tr = 0;
        map_put(&stats->branch_site_transitions, site, tr + 1);
    }
    map_put(&stats->branch_site_last_outcome, site, (uint64_t)taken);
}

static void portrait_add_ipc_tail(PortraitStats *stats, const char *line) {
    if (!stats || !line) return;
    const char *ipc = strstr(line, "IPC:");
    if (!ipc) return;
    stats->ipc_lines++;
    ipc += 4;
    while (*ipc == ' ' || *ipc == '\t') ipc++;

    char *end = NULL;
    double val = strtod(ipc, &end);
    bool had_value = false;
    if (end != ipc) {
        had_value = true;
        stats->ipc_value_count++;
        stats->ipc_value_sum += val;
        ipc = end;
    }

    const char *lp = strchr(ipc, '(');
    if (!lp) return;
    lp++;
    errno = 0;
    char *mid = NULL;
    uint64_t n = strtoull(lp, &mid, 10);
    if (errno || mid == lp || *mid != '/') return;
    errno = 0;
    char *rp = NULL;
    uint64_t d = strtoull(mid + 1, &rp, 10);
    if (errno || rp == mid + 1) return;
    stats->ipc_retire_count++;
    stats->ipc_retire_num_sum += n;
    stats->ipc_retire_den_sum += d;
    if (!had_value && d > 0) {
        stats->ipc_value_count++;
        stats->ipc_value_sum += (double)n / (double)d;
    }
}

static void portrait_add(PortraitStats *stats, const TraceInsn *insn, const TraceInsn *next, uint64_t insn_idx) {
    xed_decoded_inst_t decoded_inst;
    xed_decoded_inst_zero(&decoded_inst);
    xed_decoded_inst_set_mode(&decoded_inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed_error_enum_t err = xed_decode(&decoded_inst, (const xed_uint8_t *)insn->code, (unsigned int)insn->code_len);
    if (err != XED_ERROR_NONE) {
        stats->decode_errors++;
        return;
    }

    stats->decoded++;
    xed_category_enum_t category = xed_decoded_inst_get_category(&decoded_inst);
    xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&decoded_inst);
    if ((unsigned int)category < XED_CATEGORY_LAST) stats->categories[category]++;
    if ((unsigned int)iclass < XED_ICLASS_LAST) stats->iclasses[iclass]++;

    uint64_t branch_target = 0;
    if (category == XED_CATEGORY_COND_BR || category == XED_CATEGORY_UNCOND_BR || category == XED_CATEGORY_CALL) {
        branch_target = portrait_branch_target(insn, &decoded_inst);
    }

    if (portrait_is_branch_category(category)) stats->branches++;
    if (category == XED_CATEGORY_COND_BR) stats->cond_branches++;
    if (category == XED_CATEGORY_UNCOND_BR) {
        if (branch_target) stats->uncond_branches++;
        else stats->indirect_branches++;
    }
    if (category == XED_CATEGORY_CALL) {
        stats->calls++;
        if (branch_target) stats->direct_calls++;
        else stats->indirect_calls++;
    }
    if (category == XED_CATEGORY_RET) stats->returns++;
    if (category == XED_CATEGORY_SYSCALL || iclass == XED_ICLASS_SYSCALL || iclass == XED_ICLASS_SYSENTER) {
        stats->syscalls++;
    }

    const xed_inst_t *xi = xed_decoded_inst_inst(&decoded_inst);
    unsigned int nops = xed_inst_noperands(xi);
    OperandKind src_kind = OP_KIND_NONE;
    OperandKind dst_kind = OP_KIND_NONE;
    OperandKind explicit_kinds[4] = {OP_KIND_NONE, OP_KIND_NONE, OP_KIND_NONE, OP_KIND_NONE};
    unsigned int explicit_count = 0;

    xed_reg_enum_t regs[32];
    bool reg_reads[32];
    bool reg_writes[32];
    unsigned int reg_count = 0;

    for (unsigned int i = 0; i < nops; i++) {
        const xed_operand_t *op = xed_inst_operand(xi, i);
        xed_operand_enum_t name = xed_operand_name(op);
        xed_operand_visibility_enum_t vis = xed_operand_operand_visibility(op);
        bool reads = portrait_action_reads(op);
        bool writes = portrait_action_writes(op);
        OperandKind kind = portrait_operand_kind_from_name(name);

        if (vis == XED_OPVIS_EXPLICIT && explicit_count < 4) explicit_kinds[explicit_count++] = kind;
        if (reads && !writes && src_kind == OP_KIND_NONE) src_kind = kind;
        if (writes && dst_kind == OP_KIND_NONE) dst_kind = kind;

        if (xed_operand_is_register(name)) {
            xed_reg_enum_t reg = xed_decoded_inst_get_reg(&decoded_inst, name);
            if (reg != XED_REG_INVALID && reg_count < 32) {
                regs[reg_count] = reg;
                reg_reads[reg_count] = reads;
                reg_writes[reg_count] = writes;
                reg_count++;
            }
        }
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&decoded_inst);
    for (unsigned int mi = 0; mi < memops; mi++) {
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(&decoded_inst, mi);
        xed_reg_enum_t index = xed_decoded_inst_get_index_reg(&decoded_inst, mi);
        if (base != XED_REG_INVALID && reg_count < 32) {
            regs[reg_count] = base;
            reg_reads[reg_count] = true;
            reg_writes[reg_count] = false;
            reg_count++;
        }
        if (index != XED_REG_INVALID && reg_count < 32) {
            regs[reg_count] = index;
            reg_reads[reg_count] = true;
            reg_writes[reg_count] = false;
            reg_count++;
        }
    }

    for (unsigned int i = 0; i < reg_count; i++) {
        portrait_track_reg_deps(stats, insn->tid, regs[i], reg_reads[i], reg_writes[i], insn_idx);
    }
    for (unsigned int i = 0; i < reg_count; i++) {
        portrait_commit_reg_access(stats, insn->tid, regs[i], reg_reads[i], reg_writes[i], insn_idx);
    }

    if (src_kind != OP_KIND_NONE || dst_kind != OP_KIND_NONE) {
        stats->operand_mix[portrait_pair_opmix_kind(src_kind, dst_kind)]++;
    } else if (explicit_count >= 2) {
        stats->operand_mix[portrait_pair_opmix_kind(explicit_kinds[1], explicit_kinds[0])]++;
    } else if (explicit_count == 1) {
        stats->operand_mix[portrait_single_opmix_kind(explicit_kinds[0])]++;
    } else {
        stats->operand_mix[OPMIX_NONE]++;
    }

    if (category == XED_CATEGORY_COND_BR || category == XED_CATEGORY_UNCOND_BR || category == XED_CATEGORY_CALL) {
        portrait_add_branch_outcome(stats, insn, next, branch_target, category == XED_CATEGORY_COND_BR);
    }
}

static void write_count_array_header(FILE *out, const char *name) {
    fprintf(out, "    \"%s\": [\n", name);
}

static void write_category_counts(FILE *out, const PortraitStats *stats) {
    write_count_array_header(out, "categories");
    bool first = true;
    for (unsigned int idx = 0; idx < XED_CATEGORY_LAST; idx++) {
        if (!stats->categories[idx]) continue;
        fprintf(
            out,
            "      %s{\"name\": \"%s\", \"count\": %" PRIu64 "}",
            first ? "" : ",\n",
            xed_category_enum_t2str((xed_category_enum_t)idx),
            stats->categories[idx]
        );
        first = false;
    }
    fprintf(out, "\n    ]");
}

static void write_iclass_counts(FILE *out, const PortraitStats *stats) {
    write_count_array_header(out, "iclasses");
    bool first = true;
    for (unsigned int idx = 0; idx < XED_ICLASS_LAST; idx++) {
        if (!stats->iclasses[idx]) continue;
        fprintf(
            out,
            "      %s{\"name\": \"%s\", \"count\": %" PRIu64 "}",
            first ? "" : ",\n",
            xed_iclass_enum_t2str((xed_iclass_enum_t)idx),
            stats->iclasses[idx]
        );
        first = false;
    }
    fprintf(out, "\n    ]");
}

static const char *opmix_name(unsigned int idx) {
    switch (idx) {
        case OPMIX_REG_TO_REG: return "reg_to_reg";
        case OPMIX_REG_TO_MEM: return "reg_to_mem";
        case OPMIX_MEM_TO_REG: return "mem_to_reg";
        case OPMIX_MEM_TO_MEM: return "mem_to_mem";
        case OPMIX_IMM_TO_REG: return "imm_to_reg";
        case OPMIX_IMM_TO_MEM: return "imm_to_mem";
        case OPMIX_REG: return "reg";
        case OPMIX_MEM: return "mem";
        case OPMIX_IMM: return "imm";
        case OPMIX_NONE: return "none";
        case OPMIX_OTHER:
        default: return "other";
    }
}

static const char *dep_name(unsigned int idx) {
    switch (idx) {
        case DEP_GPR_RAW:
        case DEP_VEC_RAW: return "raw";
        case DEP_GPR_WAW:
        case DEP_VEC_WAW: return "waw";
        case DEP_GPR_WAR:
        case DEP_VEC_WAR: return "war";
        default: return "unknown";
    }
}

static double h2(double p) {
    if (p <= 0.0 || p >= 1.0) return 0.0;
    return -(p * log2(p) + (1.0 - p) * log2(1.0 - p));
}

static uint64_t map_count_or_zero(const U64Map *m, uint64_t key) {
    uint64_t v = 0;
    return map_get(m, key, &v) ? v : 0;
}

static void pattern_stats(const U64Map *m, uint64_t *out_total, uint64_t *out_max, double *out_entropy) {
    uint64_t total = 0;
    uint64_t max_count = 0;
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->used[i]) continue;
        uint64_t count = m->vals[i];
        total += count;
        if (count > max_count) max_count = count;
    }
    double entropy = 0.0;
    if (total > 0) {
        for (size_t i = 0; i < m->cap; i++) {
            if (!m->used[i]) continue;
            double p = (double)m->vals[i] / (double)total;
            if (p > 0.0) entropy -= p * log2(p);
        }
    }
    if (out_total) *out_total = total;
    if (out_max) *out_max = max_count;
    if (out_entropy) *out_entropy = entropy;
}

static void write_branch_pattern_obj(FILE *out, const U64Map *m) {
    uint64_t total = 0, max_count = 0;
    double entropy = 0.0;
    pattern_stats(m, &total, &max_count, &entropy);
    double distinct_cap = (m->sz > 0 && m->sz <= 64) ? (double)m->sz : 64.0;
    double entropy_norm = distinct_cap > 1.0 ? entropy / log2(distinct_cap) : 0.0;
    if (entropy_norm > 1.0) entropy_norm = 1.0;
    fprintf(
        out,
        "{\"samples\": %" PRIu64 ", \"distinct\": %zu, \"distinct_ratio\": %.12g, \"top_mass\": %.12g, \"entropy\": %.12g, \"entropy_norm\": %.12g}",
        total,
        m->sz,
        total ? (double)m->sz / (double)total : 0.0,
        total ? (double)max_count / (double)total : 0.0,
        entropy,
        entropy_norm
    );
}

static void write_named_counter(FILE *out, const char *name, const uint64_t *counts, unsigned int n, const char *(*name_fn)(unsigned int)) {
    fprintf(out, "    \"%s\": {\"counts\": {", name);
    bool first = true;
    uint64_t total = 0;
    for (unsigned int i = 0; i < n; i++) total += counts[i];
    for (unsigned int i = 0; i < n; i++) {
        if (!counts[i]) continue;
        fprintf(out, "%s\"%s\": %" PRIu64, first ? "" : ", ", name_fn(i), counts[i]);
        first = false;
    }
    fprintf(out, "}, \"fractions\": {");
    first = true;
    for (unsigned int i = 0; i < n; i++) {
        if (!counts[i]) continue;
        double frac = total ? (double)counts[i] / (double)total : 0.0;
        fprintf(out, "%s\"%s\": %.12g", first ? "" : ", ", name_fn(i), frac);
        first = false;
    }
    fprintf(out, "}}");
}

static void write_dep_block(FILE *out, const PortraitStats *stats, const char *name, unsigned int base) {
    fprintf(out, "    \"%s\": {\n", name);
    for (unsigned int j = 0; j < 3; j++) {
        unsigned int idx = base + j;
        uint64_t count = stats->dep_count[idx];
        double mean = count ? (double)stats->dep_sum[idx] / (double)count : 0.0;
        fprintf(out, "      \"%s\": {\"count\": %" PRIu64 ", \"mean\": %.12g, \"median\": null, \"buckets\": {",
                dep_name(idx), count, mean);
        const char *bucket_names[5] = {"0", "1-4", "5-16", "17-64", "65+"};
        bool first = true;
        for (unsigned int b = 0; b < 5; b++) {
            if (!stats->dep_buckets[idx][b]) continue;
            fprintf(out, "%s\"%s\": %" PRIu64, first ? "" : ", ", bucket_names[b], stats->dep_buckets[idx][b]);
            first = false;
        }
        fprintf(out, "}}%s\n", j == 2 ? "" : ",");
    }
    fprintf(out, "    }");
}

static void write_branch_behavior(FILE *out, const PortraitStats *stats) {
    double taken_rate = stats->branch_known ? (double)stats->branch_taken / (double)stats->branch_known : 0.0;
    double cond_taken_rate = stats->cond_branch_known ? (double)stats->cond_branch_taken / (double)stats->cond_branch_known : 0.0;
    uint64_t outcome_total = stats->branch_known + stats->branch_unknown_next_ip;
    double known_outcome_ratio = outcome_total ? (double)stats->branch_known / (double)outcome_total : 0.0;
    double site_weight = 0.0;
    double site_entropy_sum = 0.0;
    double site_transition_sum = 0.0;
    uint64_t sites_with_known = 0;
    uint64_t hot_site_count = 0;

    for (size_t i = 0; i < stats->branch_site_taken.cap; i++) {
        if (!stats->branch_site_taken.used[i]) continue;
        uint64_t key = stats->branch_site_taken.keys[i];
        uint64_t taken = stats->branch_site_taken.vals[i];
        uint64_t not_taken = map_count_or_zero(&stats->branch_site_not_taken, key);
        uint64_t known = taken + not_taken;
        if (!known) continue;
        sites_with_known++;
        if (known > hot_site_count) hot_site_count = known;
        double p = (double)taken / (double)known;
        double ent = h2(p);
        uint64_t transitions = map_count_or_zero(&stats->branch_site_transitions, key);
        double tr = known > 1 ? (double)transitions / (double)(known - 1) : 0.0;
        site_weight += (double)known;
        site_entropy_sum += ent * (double)known;
        site_transition_sum += tr * (double)known;
    }
    for (size_t i = 0; i < stats->branch_site_not_taken.cap; i++) {
        if (!stats->branch_site_not_taken.used[i]) continue;
        uint64_t key = stats->branch_site_not_taken.keys[i];
        if (map_count_or_zero(&stats->branch_site_taken, key)) continue;
        uint64_t not_taken = stats->branch_site_not_taken.vals[i];
        if (!not_taken) continue;
        sites_with_known++;
        if (not_taken > hot_site_count) hot_site_count = not_taken;
        site_weight += (double)not_taken;
        site_entropy_sum += 0.0;
        site_transition_sum += 0.0;
    }

    fprintf(out,
        "    \"branch_behavior\": {\n"
        "      \"global\": {\"known_total\": %" PRIu64 ", \"unknown_next_ip_total\": %" PRIu64 ", \"known_outcome_ratio\": %.12g, \"taken_total\": %" PRIu64 ", \"not_taken_total\": %" PRIu64 ", \"taken_rate\": %.12g, \"entropy\": %.12g, \"conditional_known_total\": %" PRIu64 ", \"conditional_unknown_next_ip_total\": %" PRIu64 ", \"conditional_taken_rate\": %.12g},\n"
        "      \"site_weighted\": {\"sites_with_known\": %" PRIu64 ", \"hot_site_top_mass\": %.12g, \"entropy_mean\": %.12g, \"transition_rate_mean\": %.12g},\n"
        "      \"patterns\": {\"4\": ",
        stats->branch_known,
        stats->branch_unknown_next_ip,
        known_outcome_ratio,
        stats->branch_taken,
        stats->branch_not_taken,
        taken_rate,
        h2(taken_rate),
        stats->cond_branch_known,
        stats->cond_branch_unknown_next_ip,
        cond_taken_rate,
        sites_with_known,
        site_weight > 0.0 ? (double)hot_site_count / site_weight : 0.0,
        site_weight > 0.0 ? site_entropy_sum / site_weight : 0.0,
        site_weight > 0.0 ? site_transition_sum / site_weight : 0.0
    );
    write_branch_pattern_obj(out, &stats->branch_pattern4);
    fprintf(out, ", \"8\": ");
    write_branch_pattern_obj(out, &stats->branch_pattern8);
    fprintf(out, ", \"16\": ");
    write_branch_pattern_obj(out, &stats->branch_pattern16);
    fprintf(out, ", \"32\": ");
    write_branch_pattern_obj(out, &stats->branch_pattern32);
    fprintf(out, "}\n    }");
}

static void write_branch_summary(FILE *out, const PortraitStats *stats) {
    const uint64_t counts[6] = {
        stats->cond_branches,
        stats->uncond_branches,
        stats->indirect_branches,
        stats->direct_calls,
        stats->indirect_calls,
        stats->returns,
    };
    const char *names[6] = {
        "conditional",
        "unconditional",
        "indirect",
        "call_direct",
        "call_indirect",
        "return",
    };
    double denom = stats->decoded ? (double)stats->decoded : 1.0;
    fprintf(out, "    \"branch\": {\"detail_counts\": {");
    for (unsigned int i = 0; i < 6; i++) {
        fprintf(out, "%s\"%s\": %" PRIu64, i ? ", " : "", names[i], counts[i]);
    }
    fprintf(out, "}, \"per_1000_insns\": {");
    for (unsigned int i = 0; i < 6; i++) {
        fprintf(out, "%s\"%s\": %.12g", i ? ", " : "", names[i], 1000.0 * (double)counts[i] / denom);
    }
    fprintf(out, "}}");
}

static void write_syscall_summary(FILE *out, const PortraitStats *stats) {
    double denom = stats->decoded ? (double)stats->decoded : 1.0;
    fprintf(
        out,
        "    \"syscall\": {\"approx_insn_count\": %" PRIu64 ", \"per_1000_insns\": %.12g}",
        stats->syscalls,
        1000.0 * (double)stats->syscalls / denom
    );
}

static void write_ipc_block(FILE *out, const PortraitStats *stats) {
    fprintf(out, "    \"ipc\": {\"annotated_blocks\": %" PRIu64, stats->ipc_lines);
    if (stats->ipc_value_count) {
        fprintf(out, ", \"values\": {\"mean\": %.12g}", stats->ipc_value_sum / (double)stats->ipc_value_count);
    } else {
        fprintf(out, ", \"values\": {}");
    }
    if (stats->ipc_retire_count) {
        double mean = 0.0;
        if (stats->ipc_retire_den_sum) {
            mean = (double)stats->ipc_retire_num_sum / (double)stats->ipc_retire_den_sum;
        }
        fprintf(out, ", \"retire_ratio\": {\"mean\": %.12g}, \"total\": {\"insns\": %" PRIu64 ", \"cycles\": %" PRIu64 ", \"ipc\": %.12g}",
                mean,
                stats->ipc_retire_num_sum,
                stats->ipc_retire_den_sum,
                stats->ipc_retire_den_sum ? (double)stats->ipc_retire_num_sum / (double)stats->ipc_retire_den_sum : 0.0);
    }
    fprintf(out, "}");
}

static char *profile_json_to_string(
    TfProfile *profile,
    const char *trace_kind,
    const char *input_format,
    uint64_t line_size,
    bool stack_depth,
    uint64_t sdp_max_lines,
    uint64_t rd_hist_cap_lines,
    uint64_t stride_bin_cap_lines
) {
    char *buffer = NULL;
    size_t buffer_size = 0;
    FILE *stream = open_memstream(&buffer, &buffer_size);
    if (!stream) return NULL;
    tf_profile_write_analysis_json(
        stream,
        profile,
        trace_kind,
        input_format,
        "stdin",
        line_size,
        stack_depth ? "stack_depth" : "distinct_since_last",
        sdp_max_lines,
        rd_hist_cap_lines,
        stride_bin_cap_lines
    );
    fclose(stream);
    return buffer;
}

static void write_combined_json(
    FILE *out,
    const ProcessorOpts *opts,
    const PortraitStats *portrait,
    TfProfile *inst_profile,
    TfProfile *data_profile,
    Ctx *ctx,
    uint64_t parsed_lines,
    uint64_t executed,
    uint64_t emu_errors,
    uint64_t invalid_insn_errors,
    uint64_t salvaged_invalid_insns
) {
    char *inst_json = profile_json_to_string(
        inst_profile,
        "inst",
        "insn_trace_stream",
        opts->analysis_line_size,
        opts->analysis_stack_depth,
        opts->analysis_sdp_max_lines,
        opts->analysis_rd_hist_cap_lines,
        opts->analysis_stride_bin_cap_lines
    );
    char *data_json = profile_json_to_string(
        data_profile,
        "data",
        "recovered_mem_stream",
        opts->analysis_line_size,
        opts->analysis_stack_depth,
        opts->analysis_sdp_max_lines,
        opts->analysis_rd_hist_cap_lines,
        opts->analysis_stride_bin_cap_lines
    );
    if (!inst_json || !data_json) die("failed to serialize profile json");

    fprintf(out, "{\n");
    fprintf(out, "  \"schema\": \"trace-profile-stream-v1\",\n");
    fprintf(out, "  \"source\": {\"input\": \"stdin\", \"format\": \"perf_script_insn_trace_tid_cpu_time_ip_insn_ipc\"},\n");
    fprintf(out, "  \"health\": {\n");
    fprintf(out, "    \"parsed_lines\": %" PRIu64 ",\n", parsed_lines);
    fprintf(out, "    \"executed_insns\": %" PRIu64 ",\n", executed);
    fprintf(out, "    \"emu_errors\": %" PRIu64 ",\n", emu_errors);
    fprintf(out, "    \"invalid_insn_errors\": %" PRIu64 ",\n", invalid_insn_errors);
    fprintf(out, "    \"salvaged_invalid_insns\": %" PRIu64 ",\n", salvaged_invalid_insns);
    fprintf(out, "    \"xed_decoded\": %" PRIu64 ",\n", portrait->decoded);
    fprintf(out, "    \"xed_decode_errors\": %" PRIu64 "\n", portrait->decode_errors);
    fprintf(out, "  },\n");

    fprintf(out, "  \"recover\": {\n");
    fprintf(out, "    \"mem_read_events\": %" PRIu64 ",\n", ctx->mem_read_events);
    fprintf(out, "    \"mem_write_events\": %" PRIu64 ",\n", ctx->mem_write_events);
    fprintf(out, "    \"mem_total_events\": %" PRIu64 ",\n", ctx->mem_read_events + ctx->mem_write_events);
    fprintf(out, "    \"syscall_events\": %" PRIu64 ",\n", ctx->syscall_events);
    fprintf(out, "    \"rcx_soft_adjusted\": %" PRIu64 ",\n", ctx->rcx_soft_adjusted);
    fprintf(out, "    \"mvs_seeded_total\": %" PRIu64 ",\n", ctx->mvs_seeded_total);
    fprintf(out, "    \"mvs_seeded_indirect\": %" PRIu64 ",\n", ctx->mvs_seeded_indirect);
    fprintf(out, "    \"mvs_seeded_normal\": %" PRIu64 ",\n", ctx->mvs_seeded_normal);
    fprintf(out, "    \"syscalls\": [\n");
    bool first_syscall = true;
    for (size_t i = 0; i < ctx->syscall_hist.cap; i++) {
        if (!ctx->syscall_hist.used[i]) continue;
        fprintf(
            out,
            "      %s{\"nr\": %" PRIu64 ", \"count\": %" PRIu64 "}\n",
            first_syscall ? "" : ",",
            ctx->syscall_hist.keys[i],
            ctx->syscall_hist.vals[i]
        );
        first_syscall = false;
    }
    fprintf(out, "    ]\n");
    fprintf(out, "  },\n");

    fprintf(out, "  \"portrait\": {\n");
    fprintf(out, "    \"stats\": {\"parsed_instructions\": %" PRIu64 ", \"skipped_lines\": %" PRIu64 ", \"lines_with_ipc_annotation\": %" PRIu64 "},\n",
            portrait->decoded,
            portrait->decode_errors,
            portrait->ipc_lines);
    fprintf(out, "    \"decoded\": %" PRIu64 ",\n", portrait->decoded);
    fprintf(out, "    \"decode_errors\": %" PRIu64 ",\n", portrait->decode_errors);
    fprintf(out, "    \"branches\": %" PRIu64 ",\n", portrait->branches);
    fprintf(out, "    \"cond_branches\": %" PRIu64 ",\n", portrait->cond_branches);
    fprintf(out, "    \"uncond_branches\": %" PRIu64 ",\n", portrait->uncond_branches);
    fprintf(out, "    \"indirect_branches\": %" PRIu64 ",\n", portrait->indirect_branches);
    fprintf(out, "    \"calls\": %" PRIu64 ",\n", portrait->calls);
    fprintf(out, "    \"direct_calls\": %" PRIu64 ",\n", portrait->direct_calls);
    fprintf(out, "    \"indirect_calls\": %" PRIu64 ",\n", portrait->indirect_calls);
    fprintf(out, "    \"returns\": %" PRIu64 ",\n", portrait->returns);
    fprintf(out, "    \"syscalls\": %" PRIu64 ",\n", portrait->syscalls);
    write_category_counts(out, portrait);
    fprintf(out, ",\n");
    write_iclass_counts(out, portrait);
    fprintf(out, ",\n");
    write_named_counter(out, "operand_mix", portrait->operand_mix, OPMIX_COUNT, opmix_name);
    fprintf(out, ",\n");
    write_branch_summary(out, portrait);
    fprintf(out, ",\n");
    write_branch_behavior(out, portrait);
    fprintf(out, ",\n");
    write_syscall_summary(out, portrait);
    fprintf(out, ",\n");
    write_ipc_block(out, portrait);
    fprintf(out, ",\n");
    write_dep_block(out, portrait, "gpr_dependency_distance", DEP_GPR_RAW);
    fprintf(out, ",\n");
    write_dep_block(out, portrait, "vec_dependency_distance", DEP_VEC_RAW);
    fprintf(out, "\n  },\n");

    fprintf(out, "  \"inst_locality\": %s,\n", inst_json);
    fprintf(out, "  \"data_locality\": %s\n", data_json);
    fprintf(out, "}\n");

    free(inst_json);
    free(data_json);
}

static FILE *open_mem_output_or_null(const char *path) {
    if (path) {
        FILE *out = fopen(path, "w");
        if (!out) die("failed to open --mem-out");
        setvbuf(out, NULL, _IOFBF, 8 << 20);
        return out;
    }
    FILE *out = fopen("/dev/null", "w");
    if (!out) die("failed to open /dev/null");
    return out;
}

int main(int argc, char **argv) {
    ProcessorOpts opts = {
        .out_path = NULL,
        .mem_out_path = NULL,
        .max_insns = 0,
        .progress_every = 0,
        .analysis_line_size = 64,
        .analysis_sdp_max_lines = 262144,
        .analysis_rd_hist_cap_lines = 262144,
        .analysis_stride_bin_cap_lines = 262144,
        .analysis_stack_depth = true,
        .split_crossline = true,
        .mvs_enable = true,
        .fast_exit = true,
        .salvage_invalid_mem = false,
        .salvage_reads = false,
        .seed = 1,
        .rcx_soft_threshold = 128,
        .code_base = 0x10000000ULL,
        .code_size = 0x20000000ULL,
        .stack_base = 0x700000000000ULL,
        .stack_size = 0x200000ULL,
        .page_size = 0x1000ULL,
    };

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--out") || !strcmp(argv[i], "-o")) {
            if (++i >= argc) die("missing value for --out");
            opts.out_path = argv[i];
        } else if (!strcmp(argv[i], "--mem-out")) {
            if (++i >= argc) die("missing value for --mem-out");
            opts.mem_out_path = argv[i];
        } else if (!strcmp(argv[i], "--max-insns")) {
            if (++i >= argc) die("missing value for --max-insns");
            opts.max_insns = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--progress-every")) {
            if (++i >= argc) die("missing value for --progress-every");
            opts.progress_every = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-line-size")) {
            if (++i >= argc) die("missing value for --analysis-line-size");
            opts.analysis_line_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-sdp-max-lines")) {
            if (++i >= argc) die("missing value for --analysis-sdp-max-lines");
            opts.analysis_sdp_max_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-rd-definition")) {
            if (++i >= argc) die("missing value for --analysis-rd-definition");
            if (!strcmp(argv[i], "stack_depth")) opts.analysis_stack_depth = true;
            else if (!strcmp(argv[i], "distinct_since_last")) opts.analysis_stack_depth = false;
            else die("invalid --analysis-rd-definition");
        } else if (!strcmp(argv[i], "--analysis-rd-hist-cap-lines")) {
            if (++i >= argc) die("missing value for --analysis-rd-hist-cap-lines");
            opts.analysis_rd_hist_cap_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-stride-bin-cap-lines")) {
            if (++i >= argc) die("missing value for --analysis-stride-bin-cap-lines");
            opts.analysis_stride_bin_cap_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--split-crossline")) {
            if (++i >= argc) die("missing value for --split-crossline");
            if (!strcmp(argv[i], "on")) opts.split_crossline = true;
            else if (!strcmp(argv[i], "off")) opts.split_crossline = false;
            else die("invalid --split-crossline");
        } else if (!strcmp(argv[i], "--mvs")) {
            if (++i >= argc) die("missing value for --mvs");
            if (!strcmp(argv[i], "on")) opts.mvs_enable = true;
            else if (!strcmp(argv[i], "off")) opts.mvs_enable = false;
            else die("invalid --mvs");
        } else if (!strcmp(argv[i], "--fast-exit")) {
            if (++i >= argc) die("missing value for --fast-exit");
            if (!strcmp(argv[i], "on")) opts.fast_exit = true;
            else if (!strcmp(argv[i], "off")) opts.fast_exit = false;
            else die("invalid --fast-exit");
        } else if (!strcmp(argv[i], "--salvage-invalid-mem")) {
            opts.salvage_invalid_mem = true;
        } else if (!strcmp(argv[i], "--salvage-reads")) {
            opts.salvage_reads = true;
        } else if (!strcmp(argv[i], "--seed")) {
            if (++i >= argc) die("missing value for --seed");
            opts.seed = (int)parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--rcx-soft-threshold")) {
            if (++i >= argc) die("missing value for --rcx-soft-threshold");
            opts.rcx_soft_threshold = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--code-base")) {
            if (++i >= argc) die("missing value for --code-base");
            opts.code_base = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--code-size")) {
            if (++i >= argc) die("missing value for --code-size");
            opts.code_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--stack-base")) {
            if (++i >= argc) die("missing value for --stack-base");
            opts.stack_base = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--stack-size")) {
            if (++i >= argc) die("missing value for --stack-size");
            opts.stack_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--page-size")) {
            if (++i >= argc) die("missing value for --page-size");
            opts.page_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            processor_usage(argv[0]);
            return 0;
        } else {
            processor_usage(argv[0]);
            die("unknown argument");
        }
    }

    if (!opts.out_path) die("--out is required");
    if ((opts.page_size & (opts.page_size - 1)) != 0) die("page-size must be power of two");
    if (opts.analysis_line_size == 0 || (opts.analysis_line_size & (opts.analysis_line_size - 1)) != 0) {
        die("analysis-line-size must be a positive power of two");
    }

    xed_tables_init();

    FILE *mem_out = open_mem_output_or_null(opts.mem_out_path);
    FILE *combined_out = fopen(opts.out_path, "w");
    if (!combined_out) die("failed to open --out");

    uc_engine *uc = NULL;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) die("uc_open failed");

    uint64_t code_limit = opts.code_base + opts.code_size;
    err = uc_mem_map(uc, opts.code_base, opts.code_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) die("uc_mem_map code failed");
    uint64_t stack_base = align_down(opts.stack_base, opts.page_size);
    uint64_t stack_size = align_up(opts.stack_size, opts.page_size);
    err = uc_mem_map(uc, stack_base, stack_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) die("uc_mem_map stack failed");
    uint64_t stack_top = stack_base + stack_size - 8;
    init_regs(uc, true, true, true, opts.seed, stack_top);

    U64Map ipmap;
    map_init(&ipmap, 1 << 16);
    uint64_t next_code = opts.code_base + 0x1000;

    U64Set pages;
    set_init(&pages, 1 << 14);
    struct {
        U64Set *pages;
        uint64_t page_sz;
        int page_init_mode;
        int page_init_seed;
    } pager_state = {
        .pages = &pages,
        .page_sz = opts.page_size,
        .page_init_mode = PAGE_INIT_ZERO,
        .page_init_seed = opts.seed,
    };

    TfProfile *inst_profile = tf_profile_create(false, opts.analysis_line_size, opts.analysis_stack_depth);
    TfProfile *data_profile = tf_profile_create(true, opts.analysis_line_size, opts.analysis_stack_depth);
    if (!inst_profile || !data_profile) die("oom profile");

    Ctx ctx = {
        .uc = uc,
        .out = mem_out,
        .cur_tid = 0,
        .cur_insn_idx = 0,
        .cur_ip = 0,
        .cur_insn = NULL,
        .rcx_soft_adjusted = 0,
        .rng_state = mix64((uint64_t)(uint32_t)opts.seed ^ 0x726378736f6674ULL),
        .mvs_enable = opts.mvs_enable,
        .mvs_bound = 0x400000000000ULL,
        .mvs_limit_lines = (1ULL << 20),
        .mvs_padding = 64,
        .mvs_cursor = 0,
        .mem_read_events = 0,
        .mem_write_events = 0,
        .syscall_events = 0,
        .analysis_line_size = opts.analysis_line_size,
        .split_crossline = opts.split_crossline,
        .data_profile = data_profile,
    };
    map_init(&ctx.mvs_pc_scope, 1 << 12);
    map_init(&ctx.mvs_pc_base, 1 << 12);
    map_init(&ctx.mvs_pc_cursor, 1 << 12);
    map_init(&ctx.mvs_pc_step, 1 << 12);
    set_init(&ctx.mvs_seeded_qw, 1 << 14);
    map_init(&ctx.syscall_hist, 1 << 10);

    uc_hook hook_read, hook_write, hook_read_unmapped, hook_write_unmapped, hook_fetch_unmapped;
    uc_hook_add(uc, &hook_read, UC_HOOK_MEM_READ, (void *)hook_mem, &ctx, 1, 0);
    uc_hook_add(uc, &hook_write, UC_HOOK_MEM_WRITE, (void *)hook_mem, &ctx, 1, 0);
    uc_hook_add(uc, &hook_read_unmapped, UC_HOOK_MEM_READ_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);
    uc_hook_add(uc, &hook_write_unmapped, UC_HOOK_MEM_WRITE_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);
    uc_hook_add(uc, &hook_fetch_unmapped, UC_HOOK_MEM_FETCH_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);

    char line[4096];
    TraceInsn prev = {0}, cur = {0};
    bool has_prev = false;
    uint64_t parsed_lines = 0;
    uint64_t executed = 0;
    uint64_t emu_errors = 0;
    uint64_t invalid_insn_errors = 0;
    uint64_t salvaged_invalid_insns = 0;
    PortraitStats portrait = {0};
    map_init(&portrait.branch_site_taken, 1 << 12);
    map_init(&portrait.branch_site_not_taken, 1 << 12);
    map_init(&portrait.branch_site_last_outcome, 1 << 12);
    map_init(&portrait.branch_site_transitions, 1 << 12);
    map_init(&portrait.branch_pattern4, 1 << 8);
    map_init(&portrait.branch_pattern8, 1 << 10);
    map_init(&portrait.branch_pattern16, 1 << 12);
    map_init(&portrait.branch_pattern32, 1 << 12);
    map_init(&portrait.gpr_last_read, 1 << 12);
    map_init(&portrait.gpr_last_write, 1 << 12);
    map_init(&portrait.vec_last_read, 1 << 12);
    map_init(&portrait.vec_last_write, 1 << 12);

    while (fgets(line, sizeof(line), stdin)) {
        portrait_add_ipc_tail(&portrait, line);
        if (!parse_trace_line(line, &cur)) continue;
        parsed_lines++;
        if (!has_prev) {
            prev = cur;
            has_prev = true;
            continue;
        }

        uint64_t cur_addr = 0, next_addr = 0;
        if (!map_get(&ipmap, prev.ip, &cur_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + prev.code_len >= code_limit) die("code region exhausted");
            map_put(&ipmap, prev.ip, addr);
            cur_addr = addr;
            next_code = addr + prev.code_len;
        }
        if (!map_get(&ipmap, cur.ip, &next_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + cur.code_len >= code_limit) die("code region exhausted");
            map_put(&ipmap, cur.ip, addr);
            next_addr = addr;
            next_code = addr + cur.code_len;
        }

        uc_mem_write(uc, cur_addr, prev.code, prev.code_len);
        uc_mem_write(uc, next_addr, cur.code, cur.code_len);

        ctx.cur_tid = prev.tid;
        ctx.cur_insn_idx = executed;
        ctx.cur_ip = prev.ip;
        ctx.cur_insn = &prev;
        tf_profile_add_inst(inst_profile, prev.tid, prev.ip);
        portrait_add(&portrait, &prev, &cur, executed);
        uc_reg_write(uc, UC_X86_REG_RIP, &cur_addr);
        apply_rcx_soft_threshold(&ctx, opts.rcx_soft_threshold, &prev);
        if (is_syscall_bytes(&prev)) {
            uint64_t rax = 0;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            syscall_hist_add(&ctx, rax);
        }
        err = uc_emu_start(uc, cur_addr, cur_addr + prev.code_len, 0, 1);
        if (err != UC_ERR_OK) {
            emu_errors++;
            if (err == UC_ERR_INSN_INVALID) {
                invalid_insn_errors++;
                if (opts.salvage_invalid_mem && salvage_invalid_mem_event(uc, &ctx, &prev, cur_addr, opts.salvage_reads)) {
                    salvaged_invalid_insns++;
                }
            }
        }
        uc_reg_write(uc, UC_X86_REG_RIP, &next_addr);

        executed++;
        if (opts.progress_every && (executed % opts.progress_every == 0)) {
            fprintf(stderr, "[progress] executed=%" PRIu64 " ip=0x%" PRIx64 "\n", executed, prev.ip);
        }
        if (opts.max_insns && executed >= opts.max_insns) break;
        prev = cur;
    }

    if (has_prev && (!opts.max_insns || executed < opts.max_insns)) {
        uint64_t last_addr = 0;
        if (!map_get(&ipmap, prev.ip, &last_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + prev.code_len >= code_limit) die("code region exhausted");
            map_put(&ipmap, prev.ip, addr);
            last_addr = addr;
        }
        uc_mem_write(uc, last_addr, prev.code, prev.code_len);
        ctx.cur_tid = prev.tid;
        ctx.cur_insn_idx = executed;
        ctx.cur_ip = prev.ip;
        ctx.cur_insn = &prev;
        tf_profile_add_inst(inst_profile, prev.tid, prev.ip);
        portrait_add(&portrait, &prev, NULL, executed);
        uc_reg_write(uc, UC_X86_REG_RIP, &last_addr);
        apply_rcx_soft_threshold(&ctx, opts.rcx_soft_threshold, &prev);
        if (is_syscall_bytes(&prev)) {
            uint64_t rax = 0;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            syscall_hist_add(&ctx, rax);
        }
        err = uc_emu_start(uc, last_addr, last_addr + prev.code_len, 0, 1);
        if (err != UC_ERR_OK) {
            emu_errors++;
            if (err == UC_ERR_INSN_INVALID) {
                invalid_insn_errors++;
                if (opts.salvage_invalid_mem && salvage_invalid_mem_event(uc, &ctx, &prev, last_addr, opts.salvage_reads)) {
                    salvaged_invalid_insns++;
                }
            }
        }
        executed++;
    }

    write_combined_json(
        combined_out,
        &opts,
        &portrait,
        inst_profile,
        data_profile,
        &ctx,
        parsed_lines,
        executed,
        emu_errors,
        invalid_insn_errors,
        salvaged_invalid_insns
    );

    if (fclose(mem_out) != 0) die("failed to close recovered memory output");
    if (fclose(combined_out) != 0) die("failed to close combined feature JSON");

    if (opts.fast_exit) {
        fprintf(
            stderr,
            "done: parsed_lines=%" PRIu64 " executed_insns=%" PRIu64 " mem_events=%" PRIu64 " xed_decoded=%" PRIu64 "\n",
            parsed_lines,
            executed,
            ctx.mem_read_events + ctx.mem_write_events,
            portrait.decoded
        );
        return 0;
    }

    map_free(&ipmap);
    set_free(&pages);
    map_free(&ctx.mvs_pc_scope);
    map_free(&ctx.mvs_pc_base);
    map_free(&ctx.mvs_pc_cursor);
    map_free(&ctx.mvs_pc_step);
    map_free(&ctx.syscall_hist);
    set_free(&ctx.mvs_seeded_qw);
    map_free(&portrait.branch_site_taken);
    map_free(&portrait.branch_site_not_taken);
    map_free(&portrait.branch_site_last_outcome);
    map_free(&portrait.branch_site_transitions);
    map_free(&portrait.branch_pattern4);
    map_free(&portrait.branch_pattern8);
    map_free(&portrait.branch_pattern16);
    map_free(&portrait.branch_pattern32);
    map_free(&portrait.gpr_last_read);
    map_free(&portrait.gpr_last_write);
    map_free(&portrait.vec_last_read);
    map_free(&portrait.vec_last_write);
    tf_profile_destroy(inst_profile);
    tf_profile_destroy(data_profile);
    uc_close(uc);
    fprintf(
        stderr,
        "done: parsed_lines=%" PRIu64 " executed_insns=%" PRIu64 " mem_events=%" PRIu64 " xed_decoded=%" PRIu64 "\n",
        parsed_lines,
        executed,
        ctx.mem_read_events + ctx.mem_write_events,
        portrait.decoded
    );
    return 0;
}
