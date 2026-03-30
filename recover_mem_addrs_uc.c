#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include "trace_feature_core.h"

#define MAX_INSN_BYTES 32

typedef struct {
    uint32_t tid;
    uint64_t ip;
    uint8_t code[MAX_INSN_BYTES];
    size_t code_len;
} TraceInsn;

typedef struct {
    uint64_t *keys;
    uint64_t *vals;
    uint8_t *used;
    size_t cap;
    size_t sz;
} U64Map;

// Forward decls (used before definitions).
static bool map_get(const U64Map *m, uint64_t k, uint64_t *out_v);
static void map_put(U64Map *m, uint64_t k, uint64_t v);

typedef struct {
    uint64_t *keys;
    uint8_t *used;
    size_t cap;
    size_t sz;
} U64Set;

typedef struct {
    uc_engine *uc;
    FILE *out;
    uint32_t cur_tid;
    uint64_t cur_insn_idx;
    uint64_t cur_ip;
    const TraceInsn *cur_insn;
    uint64_t rcx_soft_adjusted;
    uint64_t rng_state;
    bool mvs_enable;
    uint64_t mvs_bound;
    uint64_t mvs_limit_lines;
    uint64_t mvs_padding;
    uint64_t mvs_cursor;
    U64Map mvs_pc_scope;   // pc -> 0 normal, 1 indirect-like
    U64Set mvs_seeded_qw;  // seeded 8-byte slots
    uint64_t mvs_seeded_total;
    uint64_t mvs_seeded_indirect;
    uint64_t mvs_seeded_normal;
    uint64_t mem_read_events;
    uint64_t mem_write_events;
    uint64_t syscall_events;
    U64Map syscall_hist;  // syscall_nr -> count
    uint64_t analysis_line_size;
    bool split_crossline;
    TfProfile *data_profile;
} Ctx;

typedef struct {
    uint64_t code_base;
    uint64_t code_size;
    uint64_t code_limit;
    uint64_t stack_base;
    uint64_t stack_size;
    uint64_t page_size;
    uint64_t max_insns;
    uint64_t skip_insns;
    uint64_t progress_every;
    int seed;
    bool init_random;
    bool init_xmm_random;
    bool dwt_reg_staging;
    bool split_crossline;
    int page_init_mode; // 0=zero, 1=random, 2=stable
    int page_init_seed;
    uint64_t rcx_soft_threshold;
    bool mvs_enable;
    uint64_t mvs_bound;
    uint64_t mvs_limit_lines;
    uint64_t mvs_padding;
    bool salvage_invalid_mem;
    bool salvage_reads;
    bool cpu_model_set;
    int cpu_model;
    const char *cpu_model_name;
    const char *report_path;
    const char *invalid_samples_path;
    uint64_t invalid_samples_limit;
    const char *inst_analysis_path;
    const char *data_analysis_path;
    uint64_t analysis_line_size;
    uint64_t analysis_sdp_max_lines;
    bool analysis_stack_depth;
    uint64_t analysis_rd_hist_cap_lines;
    uint64_t analysis_stride_bin_cap_lines;
    const char *input_path;
    const char *output_path;
} Opts;

enum {
    PAGE_INIT_ZERO = 0,
    PAGE_INIT_RANDOM = 1,
    PAGE_INIT_STABLE = 2,
};

typedef struct {
    uint64_t insn_idx;
    uint32_t tid;
    uint64_t ip;
    uint8_t code[MAX_INSN_BYTES];
    size_t code_len;
    uint32_t err_code;
} InvalidSample;

static void mvs_seed_read_if_needed(Ctx *ctx, uint64_t address, int size);
static void mvs_mark_written(Ctx *ctx, uint64_t address, int size);

static uint64_t align_down(uint64_t x, uint64_t a) { return x & ~(a - 1); }
static uint64_t align_up(uint64_t x, uint64_t a) { return (x + (a - 1)) & ~(a - 1); }

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static int reg_id_from_gpr_index(int idx) {
    static const int regs[16] = {
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    };
    if (idx < 0 || idx >= 16) return UC_X86_REG_INVALID;
    return regs[idx];
}

static uint64_t read_gpr_by_index(uc_engine *uc, int idx) {
    int reg_id = reg_id_from_gpr_index(idx);
    if (reg_id == UC_X86_REG_INVALID) return 0;
    uint64_t v = 0;
    uc_reg_read(uc, reg_id, &v);
    return v;
}

static bool is_syscall_bytes(const TraceInsn *insn) {
    if (!insn || insn->code_len < 2) return false;
    // syscall
    if (insn->code[0] == 0x0f && insn->code[1] == 0x05) return true;
    // sysenter
    if (insn->code[0] == 0x0f && insn->code[1] == 0x34) return true;
    // int 0x80
    if (insn->code_len >= 2 && insn->code[0] == 0xcd && insn->code[1] == 0x80) return true;
    return false;
}

static void syscall_hist_add(Ctx *ctx, uint64_t nr) {
    if (!ctx) return;
    uint64_t cur = 0;
    if (!map_get(&ctx->syscall_hist, nr, &cur)) cur = 0;
    map_put(&ctx->syscall_hist, nr, cur + 1);
    ctx->syscall_events++;
}

static void emit_mem_event(Ctx *ctx, const char *kind, uint64_t address, int size, bool salvaged) {
    if (!strcmp(kind, "write")) ctx->mem_write_events++;
    else ctx->mem_read_events++;
    if (ctx->data_profile) {
        TfAccessKind ak = (!strcmp(kind, "write")) ? TF_ACCESS_WRITE : TF_ACCESS_READ;
        if (size <= 0) size = 1;
        uint64_t line_size = ctx->analysis_line_size ? ctx->analysis_line_size : 64;
        if (!ctx->split_crossline || ((address & (line_size - 1)) + (uint64_t)size <= line_size)) {
            tf_profile_add_data(ctx->data_profile, ctx->cur_tid, address, ctx->cur_ip, ak);
        } else {
            uint64_t start = address / line_size;
            uint64_t end = (address + (uint64_t)size - 1) / line_size;
            for (uint64_t ln = start; ln <= end; ln++) {
                uint64_t line_addr = ln * line_size;
                tf_profile_add_data(ctx->data_profile, ctx->cur_tid, line_addr, ctx->cur_ip, ak);
            }
        }
    }
    if (size <= 0) size = 1;
    fprintf(
        ctx->out,
        salvaged
            ? "{\"access\":\"%s\",\"addr\":\"0x%" PRIx64 "\",\"size\":%d,\"tid\":%u,\"ginsn\":%" PRIu64 ",\"salvaged\":true}\n"
            : "{\"access\":\"%s\",\"addr\":\"0x%" PRIx64 "\",\"size\":%d,\"tid\":%u,\"ginsn\":%" PRIu64 "}\n",
        kind,
        address,
        size,
        ctx->cur_tid,
        ctx->cur_insn_idx
    );
}

static bool salvage_invalid_mem_event(
    uc_engine *uc, Ctx *ctx, const TraceInsn *insn, uint64_t emu_ip, bool salvage_reads
) {
    if (insn->code_len < 4) return false;

    size_t op_idx = 0, modrm_idx = 0, pfx_end = 0;
    int vex_b_ext = 0;
    int vex_x_ext = 0;

    if (insn->code[0] == 0xC4) {
        if (insn->code_len < 5) return false;
        vex_x_ext = (~insn->code[1] >> 6) & 1;
        vex_b_ext = (~insn->code[1] >> 5) & 1;
        op_idx = 3;
        modrm_idx = 4;
        pfx_end = 3;
    } else if (insn->code[0] == 0xC5) {
        if (insn->code_len < 4) return false;
        op_idx = 2;
        modrm_idx = 3;
        pfx_end = 2;
    } else if (insn->code[0] == 0x62) {
        if (insn->code_len < 6) return false;
        vex_x_ext = (~insn->code[1] >> 6) & 1;
        vex_b_ext = (~insn->code[1] >> 5) & 1;
        op_idx = 4;
        modrm_idx = 5;
        pfx_end = 4;
    } else {
        return false;
    }

    if (modrm_idx >= insn->code_len) return false;
    uint8_t opcode = insn->code[op_idx];
    uint8_t modrm = insn->code[modrm_idx];
    int mod = (modrm >> 6) & 0x3;
    int rm_low = modrm & 0x7;
    if (mod == 3) return false; // register-only, no memory operand

    size_t cur = modrm_idx + 1;
    int64_t disp = 0;
    uint64_t base_val = 0;
    uint64_t index_val = 0;
    int scale = 1;
    bool has_base = true;
    bool rip_rel = false;

    if (rm_low == 4) {
        if (cur >= insn->code_len) return false;
        uint8_t sib = insn->code[cur++];
        int sib_scale = (sib >> 6) & 0x3;
        int idx_low = (sib >> 3) & 0x7;
        int base_low = sib & 0x7;
        scale = 1 << sib_scale;

        if (idx_low != 4) {
            int idx = idx_low | (vex_x_ext << 3);
            index_val = read_gpr_by_index(uc, idx);
        }

        if (mod == 0 && base_low == 5) {
            has_base = false;
        } else {
            int base = base_low | (vex_b_ext << 3);
            base_val = read_gpr_by_index(uc, base);
        }
    } else {
        if (mod == 0 && rm_low == 5) {
            has_base = false;
            rip_rel = true;
        } else {
            int base = rm_low | (vex_b_ext << 3);
            base_val = read_gpr_by_index(uc, base);
        }
    }

    if (mod == 1) {
        if (cur >= insn->code_len) return false;
        disp = (int8_t)insn->code[cur++];
    } else if (mod == 2 || (!has_base)) {
        if (cur + 4 > insn->code_len) return false;
        int32_t d = (int32_t)(
            ((uint32_t)insn->code[cur]) |
            ((uint32_t)insn->code[cur + 1] << 8) |
            ((uint32_t)insn->code[cur + 2] << 16) |
            ((uint32_t)insn->code[cur + 3] << 24)
        );
        disp = d;
        cur += 4;
    }

    uint64_t ea = 0;
    if (!has_base) {
        if (rip_rel) {
            ea = (emu_ip + insn->code_len + (uint64_t)disp) & 0xFFFFffffFFFFffffULL;
        } else {
            ea = ((uint64_t)disp + index_val * (uint64_t)scale) & 0xFFFFffffFFFFffffULL;
        }
    } else {
        ea = (base_val + index_val * (uint64_t)scale + (uint64_t)disp) & 0xFFFFffffFFFFffffULL;
    }

    bool do_read = true;
    bool do_write = false;
    // vmovdqu* store form writes to memory.
    if (opcode == 0x7f) {
        do_read = false;
        do_write = true;
    }

    int access_size = 8;
    // EVEX vmovdqu64 uses zmmword.
    if (insn->code[0] == 0x62 && (opcode == 0x6f || opcode == 0x7f)) access_size = 64;

    bool emitted = false;
    if (do_read && salvage_reads) {
        emit_mem_event(ctx, "read", ea, access_size, true);
        emitted = true;
    }
    if (do_write) {
        emit_mem_event(ctx, "write", ea, access_size, true);
        emitted = true;
    }
    (void)pfx_end;
    return emitted;
}

static uint64_t parse_u64_any(const char *s) {
    errno = 0;
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 0);
    if (errno || end == s || *end != '\0') die("invalid integer argument");
    return v;
}

static void normalize_model_name(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '-' || c == '_') continue;
        out[j++] = (char)tolower(c);
    }
    out[j] = '\0';
}

static int parse_x86_cpu_model(const char *name) {
    char n[128];
    normalize_model_name(name, n, sizeof(n));
    struct ModelMap { const char *name; int model; };
    static const struct ModelMap maps[] = {
        {"qemu64", UC_CPU_X86_QEMU64},
        {"phenom", UC_CPU_X86_PHENOM},
        {"core2duo", UC_CPU_X86_CORE2DUO},
        {"kvm64", UC_CPU_X86_KVM64},
        {"qemu32", UC_CPU_X86_QEMU32},
        {"kvm32", UC_CPU_X86_KVM32},
        {"coreduo", UC_CPU_X86_COREDUO},
        {"486", UC_CPU_X86_486},
        {"pentium", UC_CPU_X86_PENTIUM},
        {"pentium2", UC_CPU_X86_PENTIUM2},
        {"pentium3", UC_CPU_X86_PENTIUM3},
        {"athlon", UC_CPU_X86_ATHLON},
        {"n270", UC_CPU_X86_N270},
        {"conroe", UC_CPU_X86_CONROE},
        {"penryn", UC_CPU_X86_PENRYN},
        {"nehalem", UC_CPU_X86_NEHALEM},
        {"westmere", UC_CPU_X86_WESTMERE},
        {"sandybridge", UC_CPU_X86_SANDYBRIDGE},
        {"ivybridge", UC_CPU_X86_IVYBRIDGE},
        {"haswell", UC_CPU_X86_HASWELL},
        {"broadwell", UC_CPU_X86_BROADWELL},
        {"skylakeclient", UC_CPU_X86_SKYLAKE_CLIENT},
        {"skylakeserver", UC_CPU_X86_SKYLAKE_SERVER},
        {"cascadelakeserver", UC_CPU_X86_CASCADELAKE_SERVER},
        {"cooperlake", UC_CPU_X86_COOPERLAKE},
        {"icelakeclient", UC_CPU_X86_ICELAKE_CLIENT},
        {"icelakeserver", UC_CPU_X86_ICELAKE_SERVER},
        {"denverton", UC_CPU_X86_DENVERTON},
        {"snowridge", UC_CPU_X86_SNOWRIDGE},
        {"knightsmill", UC_CPU_X86_KNIGHTSMILL},
        {"opterong1", UC_CPU_X86_OPTERON_G1},
        {"opterong2", UC_CPU_X86_OPTERON_G2},
        {"opterong3", UC_CPU_X86_OPTERON_G3},
        {"opterong4", UC_CPU_X86_OPTERON_G4},
        {"opterong5", UC_CPU_X86_OPTERON_G5},
        {"epyc", UC_CPU_X86_EPYC},
        {"dhyana", UC_CPU_X86_DHYANA},
        {"epycrome", UC_CPU_X86_EPYC_ROME},
    };
    for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
        if (!strcmp(n, maps[i].name)) return maps[i].model;
    }
    return -1;
}

static void map_init(U64Map *m, size_t cap_pow2) {
    m->cap = cap_pow2;
    m->sz = 0;
    m->keys = (uint64_t *)calloc(m->cap, sizeof(uint64_t));
    m->vals = (uint64_t *)calloc(m->cap, sizeof(uint64_t));
    m->used = (uint8_t *)calloc(m->cap, sizeof(uint8_t));
    if (!m->keys || !m->vals || !m->used) die("oom");
}

static void map_free(U64Map *m) {
    free(m->keys);
    free(m->vals);
    free(m->used);
}

static void map_rehash(U64Map *m) {
    U64Map n;
    map_init(&n, m->cap << 1);
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->used[i]) continue;
        uint64_t k = m->keys[i];
        uint64_t v = m->vals[i];
        uint64_t h = mix64(k);
        size_t p = (size_t)(h & (n.cap - 1));
        while (n.used[p]) p = (p + 1) & (n.cap - 1);
        n.used[p] = 1;
        n.keys[p] = k;
        n.vals[p] = v;
        n.sz++;
    }
    map_free(m);
    *m = n;
}

static bool map_get(const U64Map *m, uint64_t k, uint64_t *out_v) {
    uint64_t h = mix64(k);
    size_t p = (size_t)(h & (m->cap - 1));
    while (m->used[p]) {
        if (m->keys[p] == k) {
            *out_v = m->vals[p];
            return true;
        }
        p = (p + 1) & (m->cap - 1);
    }
    return false;
}

static void map_put(U64Map *m, uint64_t k, uint64_t v) {
    if ((m->sz + 1) * 10 >= m->cap * 7) map_rehash(m);
    uint64_t h = mix64(k);
    size_t p = (size_t)(h & (m->cap - 1));
    while (m->used[p]) {
        if (m->keys[p] == k) {
            m->vals[p] = v;
            return;
        }
        p = (p + 1) & (m->cap - 1);
    }
    m->used[p] = 1;
    m->keys[p] = k;
    m->vals[p] = v;
    m->sz++;
}

static void set_init(U64Set *s, size_t cap_pow2) {
    s->cap = cap_pow2;
    s->sz = 0;
    s->keys = (uint64_t *)calloc(s->cap, sizeof(uint64_t));
    s->used = (uint8_t *)calloc(s->cap, sizeof(uint8_t));
    if (!s->keys || !s->used) die("oom");
}

static void set_free(U64Set *s) {
    free(s->keys);
    free(s->used);
}

static void set_rehash(U64Set *s) {
    U64Set n;
    set_init(&n, s->cap << 1);
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->used[i]) continue;
        uint64_t k = s->keys[i];
        uint64_t h = mix64(k);
        size_t p = (size_t)(h & (n.cap - 1));
        while (n.used[p]) p = (p + 1) & (n.cap - 1);
        n.used[p] = 1;
        n.keys[p] = k;
        n.sz++;
    }
    set_free(s);
    *s = n;
}

static bool set_has(const U64Set *s, uint64_t k) {
    uint64_t h = mix64(k);
    size_t p = (size_t)(h & (s->cap - 1));
    while (s->used[p]) {
        if (s->keys[p] == k) return true;
        p = (p + 1) & (s->cap - 1);
    }
    return false;
}

static void set_add(U64Set *s, uint64_t k) {
    if ((s->sz + 1) * 10 >= s->cap * 7) set_rehash(s);
    uint64_t h = mix64(k);
    size_t p = (size_t)(h & (s->cap - 1));
    while (s->used[p]) {
        if (s->keys[p] == k) return;
        p = (p + 1) & (s->cap - 1);
    }
    s->used[p] = 1;
    s->keys[p] = k;
    s->sz++;
}

static bool parse_trace_line(const char *line, TraceInsn *out) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!(*p >= '0' && *p <= '9')) return false;

    errno = 0;
    char *end = NULL;
    uint64_t tid = strtoull(p, &end, 10);
    if (errno || end == p) return false;
    p = end;

    while (*p == ' ' || *p == '\t') p++;
    while (*p && *p != ':') p++;
    if (*p != ':') return false;
    p++;
    while (*p == ' ' || *p == '\t') p++;

    errno = 0;
    uint64_t ip = strtoull(p, &end, 16);
    if (errno || end == p) return false;
    p = end;

    const char *q = strstr(p, "insn:");
    if (!q) return false;
    p = q + 5;

    size_t n = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!p[0] || !p[1]) break;
        char a = p[0], b = p[1];
        int hi = (a >= '0' && a <= '9') ? a - '0'
                 : (a >= 'a' && a <= 'f') ? a - 'a' + 10
                 : (a >= 'A' && a <= 'F') ? a - 'A' + 10
                 : -1;
        int lo = (b >= '0' && b <= '9') ? b - '0'
                 : (b >= 'a' && b <= 'f') ? b - 'a' + 10
                 : (b >= 'A' && b <= 'F') ? b - 'A' + 10
                 : -1;
        if (hi < 0 || lo < 0) break;
        if (n < MAX_INSN_BYTES) out->code[n++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    if (n == 0) return false;

    out->tid = (uint32_t)tid;
    out->ip = ip;
    out->code_len = n;
    return true;
}

static void ensure_page_mapped(
    uc_engine *uc,
    U64Set *pages,
    uint64_t page_base,
    uint64_t page_sz,
    int page_init_mode,
    int page_init_seed
) {
    if (set_has(pages, page_base)) return;
    uc_err e = uc_mem_map(uc, page_base, page_sz, UC_PROT_ALL);
    if (e != UC_ERR_OK) return;
    if (page_init_mode == PAGE_INIT_RANDOM) {
        uint8_t *buf = (uint8_t *)malloc((size_t)page_sz);
        if (!buf) die("oom page init");
        uint64_t x = mix64((((uint64_t)(uint32_t)page_init_seed) << 32) ^ page_base ^ 0x9e3779b97f4a7c15ULL);
        for (uint64_t i = 0; i < page_sz; i++) {
            x = mix64(x + i + 0x9e3779b97f4a7c15ULL);
            buf[i] = (uint8_t)x;
        }
        (void)uc_mem_write(uc, page_base, buf, (size_t)page_sz);
        free(buf);
    } else if (page_init_mode == PAGE_INIT_STABLE) {
        // Deterministic bounded pointer-like values to reduce page spreading.
        // Keep generated addresses in a compact 64MB window at 64B granularity.
        const uint64_t BOUND = 0x400000000000ULL;
        const uint64_t LIMIT_LINES_MASK = ((1ULL << 20) - 1); // 1,048,576 lines
        uint8_t *buf = (uint8_t *)malloc((size_t)page_sz);
        if (!buf) die("oom page init");
        for (uint64_t i = 0; i < page_sz; i += 8) {
            uint64_t h = mix64(
                (((uint64_t)(uint32_t)page_init_seed) << 32) ^
                page_base ^
                i ^
                0x9e3779b97f4a7c15ULL
            );
            uint64_t v = BOUND + ((h & LIMIT_LINES_MASK) << 6);
            size_t left = (size_t)((page_sz - i) >= 8 ? 8 : (page_sz - i));
            for (size_t b = 0; b < left; b++) {
                buf[i + b] = (uint8_t)(v >> (8 * b));
            }
        }
        (void)uc_mem_write(uc, page_base, buf, (size_t)page_sz);
        free(buf);
    }
    set_add(pages, page_base);
}

static bool hook_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    (void)type;
    (void)value;
    struct {
        U64Set *pages;
        uint64_t page_sz;
        int page_init_mode;
        int page_init_seed;
    } *st = user_data;
    if (size <= 0) size = 1;
    uint64_t start = align_down(address, st->page_sz);
    uint64_t end = align_down(address + (uint64_t)size - 1, st->page_sz);
    for (uint64_t p = start;; p += st->page_sz) {
        ensure_page_mapped(
            uc,
            st->pages,
            p,
            st->page_sz,
            st->page_init_mode,
            st->page_init_seed
        );
        if (p == end) break;
    }
    return true;
}

static void hook_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    (void)uc;
    (void)value;
    Ctx *ctx = (Ctx *)user_data;
    const char *kind = (type == UC_MEM_WRITE) ? "write" : "read";
    if (type == UC_MEM_READ) mvs_seed_read_if_needed(ctx, address, size);
    else if (type == UC_MEM_WRITE) mvs_mark_written(ctx, address, size);
    emit_mem_event(ctx, kind, address, size, false);
}

static uint64_t rng_next_u64(uint64_t *s) {
    *s = mix64(*s + 0x9e3779b97f4a7c15ULL);
    return *s;
}

static uint64_t bounded_lines_addr(uint64_t *s, uint64_t bound, uint64_t lines_mask) {
    return bound + ((rng_next_u64(s) & lines_mask) << 6);
}

static uint64_t bounded_small(uint64_t *s, uint64_t limit) {
    if (limit == 0) return 0;
    return rng_next_u64(s) % limit;
}

static bool is_rep_prefixed(const TraceInsn *insn) {
    if (!insn || insn->code_len == 0) return false;
    return (insn->code[0] == 0xF3 || insn->code[0] == 0xF2);
}

static void apply_rcx_soft_threshold(Ctx *ctx, uint64_t threshold, const TraceInsn *insn) {
    if (!ctx || threshold == 0) return;
    if (!is_rep_prefixed(insn)) return;
    uint64_t rcx = 0;
    uc_reg_read(ctx->uc, UC_X86_REG_RCX, &rcx);
    if (rcx <= threshold) return;
    // Soft thresholding: sample around threshold (roughly Gaussian-ish)
    // and clamp by the smaller of sampled value / original value.
    uint64_t base = threshold;
    uint64_t sigma = (threshold / 4) ? (threshold / 4) : 1;
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) acc += bounded_small(&ctx->rng_state, 2 * sigma + 1);
    uint64_t sampled = base + (acc / 6);
    if (sampled > rcx) sampled = rcx;
    uc_reg_write(ctx->uc, UC_X86_REG_RCX, &sampled);
    ctx->rcx_soft_adjusted++;
}

static bool looks_like_indirect_load(const TraceInsn *insn, int access_size) {
    if (!insn || insn->code_len == 0 || access_size < 8) return false;
    size_t i = 0;
    while (i < insn->code_len) {
        uint8_t b = insn->code[i];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3) {
            i++;
            continue;
        }
        if ((b & 0xF0) == 0x40) { // REX
            i++;
            continue;
        }
        break;
    }
    if (i >= insn->code_len) return false;
    uint8_t op = insn->code[i];
    // Common pointer-load forms: mov r64, [mem] and mov r64, moffs64.
    return (op == 0x8B || op == 0xA1);
}

static uint64_t mvs_seed_value(Ctx *ctx, uint64_t pc, uint64_t addr, int size) {
    if (!ctx || !ctx->mvs_enable) return 0;
    uint64_t scope = 0;
    if (!map_get(&ctx->mvs_pc_scope, pc, &scope)) {
        scope = looks_like_indirect_load(ctx->cur_insn, size) ? 1ULL : 0ULL;
        map_put(&ctx->mvs_pc_scope, pc, scope);
    }
    if (scope) {
        uint64_t lines = ctx->mvs_limit_lines ? ctx->mvs_limit_lines : (1ULL << 20);
        uint64_t window_bytes = lines << 6;
        uint64_t disp_hint = addr & 0x38ULL; // keep 8-byte alignment
        uint64_t line_off = window_bytes ? (ctx->mvs_cursor % window_bytes) : 0;
        uint64_t v = ctx->mvs_bound + line_off + disp_hint;
        uint64_t step = (ctx->mvs_padding ? ctx->mvs_padding : 64) + 64;
        if (window_bytes) ctx->mvs_cursor = (ctx->mvs_cursor + step) % window_bytes;
        else ctx->mvs_cursor += step;
        ctx->mvs_seeded_indirect++;
        return v;
    }
    uint64_t lines = ctx->mvs_limit_lines ? ctx->mvs_limit_lines : (1ULL << 20);
    uint64_t normal_base = ctx->mvs_bound + 0x1000000000ULL;
    uint64_t v = normal_base + ((rng_next_u64(&ctx->rng_state) % lines) << 6);
    ctx->mvs_seeded_normal++;
    return v;
}

static void mvs_seed_read_if_needed(Ctx *ctx, uint64_t address, int size) {
    if (!ctx || !ctx->mvs_enable || size <= 0) return;
    uint64_t start = align_down(address, 8);
    uint64_t end = align_down(address + (uint64_t)size - 1, 8);
    for (uint64_t p = start;; p += 8) {
        if (!set_has(&ctx->mvs_seeded_qw, p)) {
            uint64_t v = mvs_seed_value(ctx, ctx->cur_ip, p, size);
            (void)uc_mem_write(ctx->uc, p, &v, sizeof(v));
            set_add(&ctx->mvs_seeded_qw, p);
            ctx->mvs_seeded_total++;
        }
        if (p == end) break;
    }
}

static void mvs_mark_written(Ctx *ctx, uint64_t address, int size) {
    if (!ctx || !ctx->mvs_enable || size <= 0) return;
    uint64_t start = align_down(address, 8);
    uint64_t end = align_down(address + (uint64_t)size - 1, 8);
    for (uint64_t p = start;; p += 8) {
        if (!set_has(&ctx->mvs_seeded_qw, p)) set_add(&ctx->mvs_seeded_qw, p);
        if (p == end) break;
    }
}

static void init_regs(
    uc_engine *uc,
    bool random_init,
    bool random_xmm,
    bool dwt_reg_staging,
    int seed,
    uint64_t stack_top
) {
    int regs[] = {
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,
        UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
        UC_X86_REG_R14, UC_X86_REG_R15,
    };
    int xmm_regs[] = {
        UC_X86_REG_XMM0,  UC_X86_REG_XMM1,  UC_X86_REG_XMM2,  UC_X86_REG_XMM3,
        UC_X86_REG_XMM4,  UC_X86_REG_XMM5,  UC_X86_REG_XMM6,  UC_X86_REG_XMM7,
        UC_X86_REG_XMM8,  UC_X86_REG_XMM9,  UC_X86_REG_XMM10, UC_X86_REG_XMM11,
        UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15,
    };
    uint64_t x = (uint64_t)(uint32_t)seed;
    const uint64_t BOUND = 0x400000000000ULL;
    const uint64_t BASE_LINES_MASK = ((1ULL << 20) - 1); // 64MB in lines
    const uint64_t INDEX_LIMIT = (1ULL << 12);           // small index range
    for (size_t i = 0; i < sizeof(regs) / sizeof(regs[0]); i++) {
        uint64_t v = 0;
        if (random_init && dwt_reg_staging) {
            int r = regs[i];
            if (
                r == UC_X86_REG_RAX || r == UC_X86_REG_RBX || r == UC_X86_REG_RSI || r == UC_X86_REG_RDI ||
                r == UC_X86_REG_R8 || r == UC_X86_REG_R9 || r == UC_X86_REG_R12 || r == UC_X86_REG_R13 ||
                r == UC_X86_REG_R14 || r == UC_X86_REG_R15
            ) {
                v = bounded_lines_addr(&x, BOUND, BASE_LINES_MASK);
            } else if (r == UC_X86_REG_RCX) {
                // Keep RCX in a moderate range for rep-prefixed behavior.
                v = 1 + bounded_small(&x, 256);
            } else {
                v = bounded_small(&x, INDEX_LIMIT);
            }
        } else if (random_init) {
            x = mix64(x + 0x9e3779b97f4a7c15ULL + (uint64_t)i);
            v = x;
        }
        uc_reg_write(uc, regs[i], &v);
    }
    for (size_t i = 0; i < sizeof(xmm_regs) / sizeof(xmm_regs[0]); i++) {
        struct {
            uint64_t lo;
            uint64_t hi;
        } v = {0, 0};
        if (random_xmm) {
            x = mix64(x + 0x9e3779b97f4a7c15ULL + (uint64_t)(0x100 + i));
            v.lo = x;
            x = mix64(x + 0x9e3779b97f4a7c15ULL + (uint64_t)(0x200 + i));
            v.hi = x;
        }
        uc_reg_write(uc, xmm_regs[i], &v);
    }
    uc_reg_write(uc, UC_X86_REG_RSP, &stack_top);
    uc_reg_write(uc, UC_X86_REG_RBP, &stack_top);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -i INSN_TRACE -o OUT_JSONL [options]\n"
        "Options:\n"
        "  --max-insns N            default 0 (no limit)\n"
        "  --skip-insns N           default 0\n"
        "  --progress-every N       default 0 (disabled)\n"
        "  --init-regs zero|random  default random\n"
        "  --reg-staging legacy|dwt default dwt\n"
        "  --init-xmm zero|random   default random\n"
        "  --page-init zero|random|stable  default zero (for newly mapped pages)\n"
        "  --page-init-seed N       default --seed\n"
        "  --rcx-soft-threshold N   default 128 (0 disables)\n"
        "  --mvs on|off             default on\n"
        "  --mvs-bound N            default 0x400000000000\n"
        "  --mvs-limit-lines N      default 1048576\n"
        "  --mvs-padding N          default 64\n"
        "  --salvage-invalid-mem    decode some invalid SIMD insns and emit synthetic mem events\n"
        "  --salvage-reads          when salvage is enabled, emit synthetic reads (default off)\n"
        "  --seed N                 default 1\n"
        "  --cpu-model NAME         optional x86 cpu model (e.g. haswell, skylake-server)\n"
        "  --stack-base N           default 0x700000000000\n"
        "  --stack-size N           default 0x200000\n"
        "  --code-base N            default 0x10000000\n"
        "  --code-size N            default 0x20000000\n"
        "  --page-size N            default 0x1000\n"
        "  --report-out PATH        optional report JSON path\n"
        "  --invalid-samples-out P  optional invalid sample JSON path\n"
        "  --invalid-samples-limit N default 2000\n"
        "  --inst-analysis-out PATH optional instruction analysis JSON output\n"
        "  --data-analysis-out PATH optional recovered-data analysis JSON output\n"
        "  --analysis-line-size N   default 64\n"
        "  --analysis-sdp-max-lines N default 262144\n"
        "  --analysis-rd-definition stack_depth|distinct_since_last  default stack_depth\n"
        "  --analysis-rd-hist-cap-lines N default 262144 (0 disables cap)\n"
        "  --split-crossline on|off  default on (split memory ops spanning multiple cache lines)\n"
        "  --analysis-stride-bin-cap-lines N default 262144 (0 disables cap)\n",
        prog
    );
}

int main(int argc, char **argv) {
    Opts o = {
        .code_base = 0x10000000ULL,
        .code_size = 0x20000000ULL,
        .stack_base = 0x700000000000ULL,
        .stack_size = 0x200000ULL,
        .page_size = 0x1000ULL,
        .max_insns = 0,
        .skip_insns = 0,
        .progress_every = 0,
        .seed = 1,
        .init_random = true,
        .init_xmm_random = true,
        .dwt_reg_staging = true,
        .split_crossline = true,
        .page_init_mode = PAGE_INIT_ZERO,
        .page_init_seed = 1,
        .rcx_soft_threshold = 128,
        .mvs_enable = true,
        .mvs_bound = 0x400000000000ULL,
        .mvs_limit_lines = (1ULL << 20),
        .mvs_padding = 64,
        .salvage_invalid_mem = false,
        .salvage_reads = false,
        .cpu_model_set = false,
        .cpu_model = UC_CPU_X86_QEMU64,
        .cpu_model_name = "default",
        .report_path = NULL,
        .invalid_samples_path = NULL,
        .invalid_samples_limit = 2000,
        .inst_analysis_path = NULL,
        .data_analysis_path = NULL,
        .analysis_line_size = 64,
        .analysis_sdp_max_lines = 262144,
        .analysis_stack_depth = true,
        .analysis_rd_hist_cap_lines = 262144,
        .analysis_stride_bin_cap_lines = 262144,
        .input_path = NULL,
        .output_path = NULL,
    };

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--input")) {
            if (++i >= argc) die("missing value for --input");
            o.input_path = argv[i];
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
            if (++i >= argc) die("missing value for --output");
            o.output_path = argv[i];
        } else if (!strcmp(argv[i], "--max-insns")) {
            if (++i >= argc) die("missing value for --max-insns");
            o.max_insns = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--skip-insns")) {
            if (++i >= argc) die("missing value for --skip-insns");
            o.skip_insns = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--progress-every")) {
            if (++i >= argc) die("missing value for --progress-every");
            o.progress_every = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--seed")) {
            if (++i >= argc) die("missing value for --seed");
            o.seed = (int)parse_u64_any(argv[i]);
            o.page_init_seed = o.seed;
        } else if (!strcmp(argv[i], "--salvage-invalid-mem")) {
            o.salvage_invalid_mem = true;
        } else if (!strcmp(argv[i], "--salvage-reads")) {
            o.salvage_reads = true;
        } else if (!strcmp(argv[i], "--init-xmm")) {
            if (++i >= argc) die("missing value for --init-xmm");
            if (!strcmp(argv[i], "zero")) o.init_xmm_random = false;
            else if (!strcmp(argv[i], "random")) o.init_xmm_random = true;
            else die("invalid --init-xmm");
        } else if (!strcmp(argv[i], "--reg-staging")) {
            if (++i >= argc) die("missing value for --reg-staging");
            if (!strcmp(argv[i], "legacy")) o.dwt_reg_staging = false;
            else if (!strcmp(argv[i], "dwt")) o.dwt_reg_staging = true;
            else die("invalid --reg-staging");
        } else if (!strcmp(argv[i], "--page-init")) {
            if (++i >= argc) die("missing value for --page-init");
            if (!strcmp(argv[i], "zero")) o.page_init_mode = PAGE_INIT_ZERO;
            else if (!strcmp(argv[i], "random")) o.page_init_mode = PAGE_INIT_RANDOM;
            else if (!strcmp(argv[i], "stable")) o.page_init_mode = PAGE_INIT_STABLE;
            else die("invalid --page-init");
        } else if (!strcmp(argv[i], "--page-init-seed")) {
            if (++i >= argc) die("missing value for --page-init-seed");
            o.page_init_seed = (int)parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--rcx-soft-threshold")) {
            if (++i >= argc) die("missing value for --rcx-soft-threshold");
            o.rcx_soft_threshold = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--mvs")) {
            if (++i >= argc) die("missing value for --mvs");
            if (!strcmp(argv[i], "on")) o.mvs_enable = true;
            else if (!strcmp(argv[i], "off")) o.mvs_enable = false;
            else die("invalid --mvs");
        } else if (!strcmp(argv[i], "--mvs-bound")) {
            if (++i >= argc) die("missing value for --mvs-bound");
            o.mvs_bound = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--mvs-limit-lines")) {
            if (++i >= argc) die("missing value for --mvs-limit-lines");
            o.mvs_limit_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--mvs-padding")) {
            if (++i >= argc) die("missing value for --mvs-padding");
            o.mvs_padding = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--cpu-model")) {
            if (++i >= argc) die("missing value for --cpu-model");
            int m = parse_x86_cpu_model(argv[i]);
            if (m < 0) die("invalid --cpu-model");
            o.cpu_model_set = true;
            o.cpu_model = m;
            o.cpu_model_name = argv[i];
        } else if (!strcmp(argv[i], "--init-regs")) {
            if (++i >= argc) die("missing value for --init-regs");
            if (!strcmp(argv[i], "zero")) o.init_random = false;
            else if (!strcmp(argv[i], "random")) o.init_random = true;
            else die("invalid --init-regs");
        } else if (!strcmp(argv[i], "--stack-base")) {
            if (++i >= argc) die("missing value for --stack-base");
            o.stack_base = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--stack-size")) {
            if (++i >= argc) die("missing value for --stack-size");
            o.stack_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--code-base")) {
            if (++i >= argc) die("missing value for --code-base");
            o.code_base = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--code-size")) {
            if (++i >= argc) die("missing value for --code-size");
            o.code_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--page-size")) {
            if (++i >= argc) die("missing value for --page-size");
            o.page_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--report-out")) {
            if (++i >= argc) die("missing value for --report-out");
            o.report_path = argv[i];
        } else if (!strcmp(argv[i], "--invalid-samples-out")) {
            if (++i >= argc) die("missing value for --invalid-samples-out");
            o.invalid_samples_path = argv[i];
        } else if (!strcmp(argv[i], "--invalid-samples-limit")) {
            if (++i >= argc) die("missing value for --invalid-samples-limit");
            o.invalid_samples_limit = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--inst-analysis-out")) {
            if (++i >= argc) die("missing value for --inst-analysis-out");
            o.inst_analysis_path = argv[i];
        } else if (!strcmp(argv[i], "--data-analysis-out")) {
            if (++i >= argc) die("missing value for --data-analysis-out");
            o.data_analysis_path = argv[i];
        } else if (!strcmp(argv[i], "--analysis-line-size")) {
            if (++i >= argc) die("missing value for --analysis-line-size");
            o.analysis_line_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-sdp-max-lines")) {
            if (++i >= argc) die("missing value for --analysis-sdp-max-lines");
            o.analysis_sdp_max_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--analysis-rd-definition")) {
            if (++i >= argc) die("missing value for --analysis-rd-definition");
            if (!strcmp(argv[i], "stack_depth")) o.analysis_stack_depth = true;
            else if (!strcmp(argv[i], "distinct_since_last")) o.analysis_stack_depth = false;
            else die("invalid --analysis-rd-definition");
        } else if (!strcmp(argv[i], "--analysis-rd-hist-cap-lines")) {
            if (++i >= argc) die("missing value for --analysis-rd-hist-cap-lines");
            o.analysis_rd_hist_cap_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--split-crossline")) {
            if (++i >= argc) die("missing value for --split-crossline");
            if (!strcmp(argv[i], "on")) o.split_crossline = true;
            else if (!strcmp(argv[i], "off")) o.split_crossline = false;
            else die("invalid --split-crossline (use on|off)");
        } else if (!strcmp(argv[i], "--analysis-stride-bin-cap-lines")) {
            if (++i >= argc) die("missing value for --analysis-stride-bin-cap-lines");
            o.analysis_stride_bin_cap_lines = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            die("unknown argument");
        }
    }

    if (!o.input_path || !o.output_path) die("input/output required");
    if ((o.page_size & (o.page_size - 1)) != 0) die("page-size must be power of two");
    if (o.analysis_line_size == 0 || (o.analysis_line_size & (o.analysis_line_size - 1)) != 0) {
        die("analysis-line-size must be a positive power of two");
    }
    if (o.analysis_sdp_max_lines == 0) die("analysis-sdp-max-lines must be > 0");
    if (o.mvs_enable && o.mvs_limit_lines == 0) die("mvs-limit-lines must be > 0 when mvs is on");

    o.code_limit = o.code_base + o.code_size;

    FILE *fin = fopen(o.input_path, "r");
    if (!fin) die("failed to open input");
    FILE *fout = fopen(o.output_path, "w");
    if (!fout) die("failed to open output");
    setvbuf(fout, NULL, _IOFBF, 8 << 20);

    uc_engine *uc = NULL;
    uc_err e = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (e != UC_ERR_OK) die("uc_open failed");
    if (o.cpu_model_set) {
        e = uc_ctl_set_cpu_model(uc, o.cpu_model);
        if (e != UC_ERR_OK) die("uc_ctl_set_cpu_model failed");
    }

    e = uc_mem_map(uc, o.code_base, o.code_size, UC_PROT_ALL);
    if (e != UC_ERR_OK) die("uc_mem_map code failed");
    uint64_t stack_base = align_down(o.stack_base, o.page_size);
    uint64_t stack_size = align_up(o.stack_size, o.page_size);
    e = uc_mem_map(uc, stack_base, stack_size, UC_PROT_ALL);
    if (e != UC_ERR_OK) die("uc_mem_map stack failed");
    uint64_t stack_top = stack_base + stack_size - 8;
    init_regs(uc, o.init_random, o.init_xmm_random, o.dwt_reg_staging, o.seed, stack_top);

    U64Map ipmap;
    map_init(&ipmap, 1 << 16);
    uint64_t next_code = o.code_base + 0x1000;

    U64Set pages;
    set_init(&pages, 1 << 14);

    struct {
        U64Set *pages;
        uint64_t page_sz;
        int page_init_mode;
        int page_init_seed;
    } pager_state = {
        .pages = &pages,
        .page_sz = o.page_size,
        .page_init_mode = o.page_init_mode,
        .page_init_seed = o.page_init_seed,
    };

    Ctx ctx = {
        .uc = uc,
        .out = fout,
        .cur_tid = 0,
        .cur_insn_idx = 0,
        .cur_ip = 0,
        .cur_insn = NULL,
        .rcx_soft_adjusted = 0,
        .rng_state = mix64((uint64_t)(uint32_t)o.seed ^ 0x726378736f6674ULL),
        .mvs_enable = o.mvs_enable,
        .mvs_bound = o.mvs_bound,
        .mvs_limit_lines = o.mvs_limit_lines,
        .mvs_padding = o.mvs_padding,
        .mvs_cursor = 0,
        .mem_read_events = 0,
        .mem_write_events = 0,
        .syscall_events = 0,
        .analysis_line_size = o.analysis_line_size,
        .split_crossline = o.split_crossline,
        .data_profile = NULL,
    };
    map_init(&ctx.mvs_pc_scope, 1 << 12);
    set_init(&ctx.mvs_seeded_qw, 1 << 14);
    map_init(&ctx.syscall_hist, 1 << 10);
    TfProfile *inst_profile = NULL;
    if (o.inst_analysis_path) {
        inst_profile = tf_profile_create(false, o.analysis_line_size, o.analysis_stack_depth);
        if (!inst_profile) die("oom inst profile");
    }
    if (o.data_analysis_path) {
        ctx.data_profile = tf_profile_create(false, o.analysis_line_size, o.analysis_stack_depth);
        if (!ctx.data_profile) die("oom data profile");
    }
    uc_hook hh1, hh2, hh3, hh4, hh5;
    uc_hook_add(uc, &hh1, UC_HOOK_MEM_READ, (void *)hook_mem, &ctx, 1, 0);
    uc_hook_add(uc, &hh2, UC_HOOK_MEM_WRITE, (void *)hook_mem, &ctx, 1, 0);
    uc_hook_add(uc, &hh3, UC_HOOK_MEM_READ_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);
    uc_hook_add(uc, &hh4, UC_HOOK_MEM_WRITE_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);
    uc_hook_add(uc, &hh5, UC_HOOK_MEM_FETCH_UNMAPPED, (void *)hook_unmapped, &pager_state, 1, 0);

    char line[4096];
    TraceInsn prev = {0}, cur = {0};
    bool has_prev = false;
    uint64_t seen = 0;
    uint64_t executed = 0;
    uint64_t skipped = 0;
    uint64_t emu_errors = 0;
    uint64_t invalid_insn_errors = 0;
    uint64_t salvaged_invalid_insns = 0;
    InvalidSample *invalid_samples = NULL;
    uint64_t invalid_samples_cap = 0;
    uint64_t invalid_samples_cnt = 0;

    while (fgets(line, sizeof(line), fin)) {
        if (!parse_trace_line(line, &cur)) continue;
        if (skipped < o.skip_insns) {
            skipped++;
            continue;
        }
        if (!has_prev) {
            prev = cur;
            has_prev = true;
            continue;
        }
        uint64_t cur_addr = 0, nxt_addr = 0;
        if (!map_get(&ipmap, prev.ip, &cur_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + prev.code_len >= o.code_limit) die("code region exhausted");
            map_put(&ipmap, prev.ip, addr);
            cur_addr = addr;
            next_code = addr + prev.code_len;
        }
        if (!map_get(&ipmap, cur.ip, &nxt_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + cur.code_len >= o.code_limit) die("code region exhausted");
            map_put(&ipmap, cur.ip, addr);
            nxt_addr = addr;
            next_code = addr + cur.code_len;
        }

        uc_mem_write(uc, cur_addr, prev.code, prev.code_len);
        uc_mem_write(uc, nxt_addr, cur.code, cur.code_len);

        ctx.cur_tid = prev.tid;
        ctx.cur_insn_idx = executed;
        ctx.cur_ip = prev.ip;
        ctx.cur_insn = &prev;
        if (inst_profile) tf_profile_add_inst(inst_profile, prev.tid, prev.ip);
        uc_reg_write(uc, UC_X86_REG_RIP, &cur_addr);
        apply_rcx_soft_threshold(&ctx, o.rcx_soft_threshold, &prev);
        if (is_syscall_bytes(&prev)) {
            uint64_t rax = 0;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            syscall_hist_add(&ctx, rax);
        }
        e = uc_emu_start(uc, cur_addr, cur_addr + prev.code_len, 0, 1);
        if (e != UC_ERR_OK) {
            emu_errors++;
            if (e == UC_ERR_INSN_INVALID) {
                invalid_insn_errors++;
                if (o.salvage_invalid_mem &&
                    salvage_invalid_mem_event(uc, &ctx, &prev, cur_addr, o.salvage_reads)) {
                    salvaged_invalid_insns++;
                }
                if (o.invalid_samples_path && invalid_samples_cnt < o.invalid_samples_limit) {
                    if (invalid_samples_cnt == invalid_samples_cap) {
                        uint64_t new_cap = (invalid_samples_cap == 0) ? 256 : invalid_samples_cap * 2;
                        if (new_cap > o.invalid_samples_limit) new_cap = o.invalid_samples_limit;
                        InvalidSample *tmp = (InvalidSample *)realloc(
                            invalid_samples, (size_t)new_cap * sizeof(InvalidSample)
                        );
                        if (!tmp) die("oom invalid_samples realloc");
                        invalid_samples = tmp;
                        invalid_samples_cap = new_cap;
                    }
                    InvalidSample *s = &invalid_samples[invalid_samples_cnt++];
                    s->insn_idx = executed;
                    s->tid = prev.tid;
                    s->ip = prev.ip;
                    s->code_len = prev.code_len;
                    memcpy(s->code, prev.code, prev.code_len);
                    s->err_code = (uint32_t)e;
                }
            }
        }
        uc_reg_write(uc, UC_X86_REG_RIP, &nxt_addr);

        executed++;
        seen++;
        if (o.progress_every && (executed % o.progress_every == 0)) {
            fprintf(stderr, "[progress] executed=%" PRIu64 " ip=0x%" PRIx64 "\n", executed, prev.ip);
        }
        if (o.max_insns && executed >= o.max_insns) break;
        prev = cur;
    }

    if (has_prev && (!o.max_insns || executed < o.max_insns)) {
        uint64_t last_addr = 0;
        if (!map_get(&ipmap, prev.ip, &last_addr)) {
            uint64_t addr = align_up(next_code, 16);
            if (addr + prev.code_len >= o.code_limit) die("code region exhausted");
            map_put(&ipmap, prev.ip, addr);
            last_addr = addr;
        }
        uc_mem_write(uc, last_addr, prev.code, prev.code_len);
        ctx.cur_tid = prev.tid;
        ctx.cur_insn_idx = executed;
        ctx.cur_ip = prev.ip;
        ctx.cur_insn = &prev;
        if (inst_profile) tf_profile_add_inst(inst_profile, prev.tid, prev.ip);
        uc_reg_write(uc, UC_X86_REG_RIP, &last_addr);
        apply_rcx_soft_threshold(&ctx, o.rcx_soft_threshold, &prev);
        if (is_syscall_bytes(&prev)) {
            uint64_t rax = 0;
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
            syscall_hist_add(&ctx, rax);
        }
        e = uc_emu_start(uc, last_addr, last_addr + prev.code_len, 0, 1);
        if (e != UC_ERR_OK) {
            emu_errors++;
            if (e == UC_ERR_INSN_INVALID) {
                invalid_insn_errors++;
                if (o.salvage_invalid_mem &&
                    salvage_invalid_mem_event(uc, &ctx, &prev, last_addr, o.salvage_reads)) {
                    salvaged_invalid_insns++;
                }
                if (o.invalid_samples_path && invalid_samples_cnt < o.invalid_samples_limit) {
                    if (invalid_samples_cnt == invalid_samples_cap) {
                        uint64_t new_cap = (invalid_samples_cap == 0) ? 256 : invalid_samples_cap * 2;
                        if (new_cap > o.invalid_samples_limit) new_cap = o.invalid_samples_limit;
                        InvalidSample *tmp = (InvalidSample *)realloc(
                            invalid_samples, (size_t)new_cap * sizeof(InvalidSample)
                        );
                        if (!tmp) die("oom invalid_samples realloc");
                        invalid_samples = tmp;
                        invalid_samples_cap = new_cap;
                    }
                    InvalidSample *s = &invalid_samples[invalid_samples_cnt++];
                    s->insn_idx = executed;
                    s->tid = prev.tid;
                    s->ip = prev.ip;
                    s->code_len = prev.code_len;
                    memcpy(s->code, prev.code, prev.code_len);
                    s->err_code = (uint32_t)e;
                }
            }
        }
        executed++;
    }

    fprintf(stderr, "done: executed_insns=%" PRIu64 " parsed_steps=%" PRIu64 "\n", executed, seen);
    fprintf(
        stderr,
        "events: read=%" PRIu64 " write=%" PRIu64 " total=%" PRIu64 "\n",
        ctx.mem_read_events,
        ctx.mem_write_events,
        ctx.mem_read_events + ctx.mem_write_events
    );
    fprintf(
        stderr,
        "emu_errors=%" PRIu64 " invalid_insn=%" PRIu64 "\n",
        emu_errors,
        invalid_insn_errors
    );
    fprintf(stderr, "dwt: rcx_soft_adjusted=%" PRIu64 "\n", ctx.rcx_soft_adjusted);
    if (ctx.mvs_enable) {
        fprintf(
            stderr,
            "dwt: mvs_seeded_total=%" PRIu64 " indirect=%" PRIu64 " normal=%" PRIu64 "\n",
            ctx.mvs_seeded_total,
            ctx.mvs_seeded_indirect,
            ctx.mvs_seeded_normal
        );
    }

    if (o.report_path) {
        FILE *fr = fopen(o.report_path, "w");
        if (fr) {
            fprintf(
                fr,
                "{\n"
                "  \"input\": \"%s\",\n"
                "  \"output\": \"%s\",\n"
                "  \"cpu_model\": \"%s\",\n"
                "  \"executed_insns\": %" PRIu64 ",\n"
                "  \"parsed_steps\": %" PRIu64 ",\n"
                "  \"mem_read_events\": %" PRIu64 ",\n"
                "  \"mem_write_events\": %" PRIu64 ",\n"
                "  \"mem_total_events\": %" PRIu64 ",\n"
                "  \"syscall_events\": %" PRIu64 ",\n"
                "  \"emu_errors\": %" PRIu64 ",\n"
                "  \"invalid_insn_errors\": %" PRIu64 ",\n"
                "  \"salvaged_invalid_insns\": %" PRIu64 ",\n"
                "  \"rcx_soft_adjusted\": %" PRIu64 ",\n"
                "  \"mvs_seeded_total\": %" PRIu64 ",\n"
                "  \"mvs_seeded_indirect\": %" PRIu64 ",\n"
                "  \"mvs_seeded_normal\": %" PRIu64 ",\n"
                "  \"invalid_samples_written\": %" PRIu64 ",\n"
                "  \"syscalls\": [\n",
                o.input_path,
                o.output_path,
                o.cpu_model_name,
                executed,
                seen,
                ctx.mem_read_events,
                ctx.mem_write_events,
                ctx.mem_read_events + ctx.mem_write_events,
                ctx.syscall_events,
                emu_errors,
                invalid_insn_errors,
                salvaged_invalid_insns,
                ctx.rcx_soft_adjusted,
                ctx.mvs_seeded_total,
                ctx.mvs_seeded_indirect,
                ctx.mvs_seeded_normal,
                invalid_samples_cnt
            );
            bool first = true;
            for (size_t i = 0; i < ctx.syscall_hist.cap; i++) {
                if (!ctx.syscall_hist.used[i]) continue;
                fprintf(
                    fr,
                    "    %s{\"nr\": %" PRIu64 ", \"count\": %" PRIu64 "}\n",
                    first ? "" : ",",
                    ctx.syscall_hist.keys[i],
                    ctx.syscall_hist.vals[i]
                );
                first = false;
            }
            fprintf(fr, "  ]\n}\n");
            fclose(fr);
        }
    }

    if (o.invalid_samples_path) {
        FILE *fs = fopen(o.invalid_samples_path, "w");
        if (fs) {
            fprintf(
                fs,
                "{\n"
                "  \"input\": \"%s\",\n"
                "  \"cpu_model\": \"%s\",\n"
                "  \"executed_insns\": %" PRIu64 ",\n"
                "  \"invalid_insn_errors\": %" PRIu64 ",\n"
                "  \"salvaged_invalid_insns\": %" PRIu64 ",\n"
                "  \"samples_limit\": %" PRIu64 ",\n"
                "  \"samples_written\": %" PRIu64 ",\n"
                "  \"samples\": [\n",
                o.input_path,
                o.cpu_model_name,
                executed,
                invalid_insn_errors,
                salvaged_invalid_insns,
                o.invalid_samples_limit,
                invalid_samples_cnt
            );
            for (uint64_t i = 0; i < invalid_samples_cnt; i++) {
                InvalidSample *s = &invalid_samples[i];
                char hexbuf[MAX_INSN_BYTES * 2 + 1];
                for (size_t j = 0; j < s->code_len; j++) {
                    snprintf(&hexbuf[j * 2], 3, "%02x", s->code[j]);
                }
                hexbuf[s->code_len * 2] = '\0';
                fprintf(
                    fs,
                    "    {\"insn_idx\": %" PRIu64 ", \"tid\": %" PRIu32 ", \"ip\": \"0x%" PRIx64
                    "\", \"bytes\": \"%s\", \"err_code\": %" PRIu32 "}%s\n",
                    s->insn_idx,
                    s->tid,
                    s->ip,
                    hexbuf,
                    s->err_code,
                    (i + 1 == invalid_samples_cnt) ? "" : ","
                );
            }
            fprintf(fs, "  ]\n}\n");
            fclose(fs);
        }
    }

    if (o.inst_analysis_path && inst_profile) {
        FILE *fa = fopen(o.inst_analysis_path, "w");
        if (fa) {
            tf_profile_write_analysis_json(
                fa,
                inst_profile,
                "inst",
                "insn_trace",
                o.input_path,
                o.analysis_line_size,
                o.analysis_stack_depth ? "stack_depth" : "distinct_since_last",
                o.analysis_sdp_max_lines,
                o.analysis_rd_hist_cap_lines,
                o.analysis_stride_bin_cap_lines
            );
            fclose(fa);
        }
    }
    if (o.data_analysis_path && ctx.data_profile) {
        FILE *fa = fopen(o.data_analysis_path, "w");
        if (fa) {
            tf_profile_write_analysis_json(
                fa,
                ctx.data_profile,
                "data",
                "mem_jsonl",
                o.output_path,
                o.analysis_line_size,
                o.analysis_stack_depth ? "stack_depth" : "distinct_since_last",
                o.analysis_sdp_max_lines,
                o.analysis_rd_hist_cap_lines,
                o.analysis_stride_bin_cap_lines
            );
            fclose(fa);
        }
    }

    map_free(&ipmap);
    set_free(&pages);
    map_free(&ctx.mvs_pc_scope);
    map_free(&ctx.syscall_hist);
    set_free(&ctx.mvs_seeded_qw);
    free(invalid_samples);
    tf_profile_destroy(inst_profile);
    tf_profile_destroy(ctx.data_profile);
    uc_close(uc);
    fclose(fin);
    fclose(fout);
    return 0;
}
