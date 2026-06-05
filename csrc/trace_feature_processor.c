#define _GNU_SOURCE

#define main recover_mem_addrs_uc_legacy_main
#include "recover_mem_addrs_uc.c"
#undef main

#include <xed/xed-interface.h>

#include <unistd.h>

typedef struct {
    uint64_t decoded;
    uint64_t decode_errors;
    uint64_t categories[XED_CATEGORY_LAST];
    uint64_t iclasses[XED_ICLASS_LAST];
    uint64_t branches;
    uint64_t cond_branches;
    uint64_t calls;
    uint64_t returns;
    uint64_t syscalls;
} PortraitStats;

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

static void portrait_add(PortraitStats *stats, const TraceInsn *insn) {
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

    if (portrait_is_branch_category(category)) stats->branches++;
    if (category == XED_CATEGORY_COND_BR) stats->cond_branches++;
    if (category == XED_CATEGORY_CALL) stats->calls++;
    if (category == XED_CATEGORY_RET) stats->returns++;
    if (category == XED_CATEGORY_SYSCALL || iclass == XED_ICLASS_SYSCALL || iclass == XED_ICLASS_SYSENTER) {
        stats->syscalls++;
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
    fprintf(out, "    \"mvs_seeded_normal\": %" PRIu64 "\n", ctx->mvs_seeded_normal);
    fprintf(out, "  },\n");

    fprintf(out, "  \"portrait\": {\n");
    fprintf(out, "    \"decoded\": %" PRIu64 ",\n", portrait->decoded);
    fprintf(out, "    \"decode_errors\": %" PRIu64 ",\n", portrait->decode_errors);
    fprintf(out, "    \"branches\": %" PRIu64 ",\n", portrait->branches);
    fprintf(out, "    \"cond_branches\": %" PRIu64 ",\n", portrait->cond_branches);
    fprintf(out, "    \"calls\": %" PRIu64 ",\n", portrait->calls);
    fprintf(out, "    \"returns\": %" PRIu64 ",\n", portrait->returns);
    fprintf(out, "    \"syscalls\": %" PRIu64 ",\n", portrait->syscalls);
    write_category_counts(out, portrait);
    fprintf(out, ",\n");
    write_iclass_counts(out, portrait);
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
    TfProfile *data_profile = tf_profile_create(false, opts.analysis_line_size, opts.analysis_stack_depth);
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

    while (fgets(line, sizeof(line), stdin)) {
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
        portrait_add(&portrait, &prev);
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
        portrait_add(&portrait, &prev);
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

    fprintf(
        stderr,
        "done: parsed_lines=%" PRIu64 " executed_insns=%" PRIu64 " mem_events=%" PRIu64 " xed_decoded=%" PRIu64 "\n",
        parsed_lines,
        executed,
        ctx.mem_read_events + ctx.mem_write_events,
        portrait.decoded
    );

    map_free(&ipmap);
    set_free(&pages);
    map_free(&ctx.mvs_pc_scope);
    map_free(&ctx.mvs_pc_base);
    map_free(&ctx.mvs_pc_cursor);
    map_free(&ctx.mvs_pc_step);
    map_free(&ctx.syscall_hist);
    set_free(&ctx.mvs_seeded_qw);
    tf_profile_destroy(inst_profile);
    tf_profile_destroy(data_profile);
    uc_close(uc);
    fclose(mem_out);
    fclose(combined_out);
    return 0;
}
