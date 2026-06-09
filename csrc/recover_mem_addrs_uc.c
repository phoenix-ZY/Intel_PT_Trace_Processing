/* Library included by trace_feature_processor.c — not a standalone program. */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    U64Map mvs_pc_scope;   // pc -> MvsSeedScope
    U64Map mvs_pc_base;    // pc -> synthetic region base
    U64Map mvs_pc_cursor;  // pc -> next byte offset within region
    U64Map mvs_pc_step;    // pc -> stream step in bytes
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

enum {
    PAGE_INIT_ZERO = 0,
    PAGE_INIT_RANDOM = 1,
    PAGE_INIT_STABLE = 2,
};

typedef enum {
    MVS_SCOPE_NORMAL = 0,
    MVS_SCOPE_POINTER = 1,
    MVS_SCOPE_STACK = 2,
    MVS_SCOPE_GLOBAL = 3,
    MVS_SCOPE_ARRAY = 4,
} MvsSeedScope;

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
            ? "{\"access\":\"%s\",\"addr\":\"0x%" PRIx64 "\",\"size\":%d,\"tid\":%u,\"ginsn\":%" PRIu64 ",\"ip\":\"0x%" PRIx64 "\",\"salvaged\":true}\n"
            : "{\"access\":\"%s\",\"addr\":\"0x%" PRIx64 "\",\"size\":%d,\"tid\":%u,\"ginsn\":%" PRIu64 ",\"ip\":\"0x%" PRIx64 "\"}\n",
        kind,
        address,
        size,
        ctx->cur_tid,
        ctx->cur_insn_idx,
        ctx->cur_ip
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

static bool parse_memory_operand_shape(
    const TraceInsn *insn,
    bool *has_index,
    bool *uses_stack_base,
    bool *is_rip_relative,
    int *scale_out
) {
    if (!insn || insn->code_len == 0) return false;

    size_t pos = 0;
    int rex_b_ext = 0;
    int rex_x_ext = 0;
    while (pos < insn->code_len) {
        uint8_t byte = insn->code[pos];
        if (byte == 0x66 || byte == 0x67 || byte == 0xF0 || byte == 0xF2 || byte == 0xF3) {
            pos++;
            continue;
        }
        if ((byte & 0xF0) == 0x40) {
            rex_b_ext = byte & 0x1;
            rex_x_ext = (byte >> 1) & 0x1;
            pos++;
            continue;
        }
        break;
    }
    if (pos >= insn->code_len) return false;

    uint8_t opcode = insn->code[pos++];
    if (opcode == 0x0F) {
        if (pos >= insn->code_len) return false;
        opcode = insn->code[pos++];
        (void)opcode;
    } else if (opcode == 0xA0 || opcode == 0xA1 || opcode == 0xA2 || opcode == 0xA3) {
        *is_rip_relative = false;
        *uses_stack_base = false;
        *has_index = false;
        *scale_out = 1;
        return true;
    }

    if (pos >= insn->code_len) return false;
    uint8_t modrm = insn->code[pos++];
    int mod = (modrm >> 6) & 0x3;
    int rm_low = modrm & 0x7;
    if (mod == 3) return false;

    *has_index = false;
    *uses_stack_base = false;
    *is_rip_relative = false;
    *scale_out = 1;

    if (rm_low == 4) {
        if (pos >= insn->code_len) return false;
        uint8_t sib = insn->code[pos++];
        int sib_scale = (sib >> 6) & 0x3;
        int index_low = (sib >> 3) & 0x7;
        int base_low = sib & 0x7;
        int index_reg = index_low | (rex_x_ext << 3);
        int base_reg = base_low | (rex_b_ext << 3);
        *scale_out = 1 << sib_scale;
        *has_index = index_low != 4;
        if (index_reg == 4) *has_index = false;
        if (base_reg == 4 || base_reg == 5) *uses_stack_base = true;
        if (mod == 0 && base_low == 5) *uses_stack_base = false;
    } else {
        int base_reg = rm_low | (rex_b_ext << 3);
        if (mod == 0 && rm_low == 5) {
            *is_rip_relative = true;
        } else if (base_reg == 4 || base_reg == 5) {
            *uses_stack_base = true;
        }
    }

    return true;
}

static MvsSeedScope classify_mvs_seed_scope(const TraceInsn *insn, int access_size) {
    bool has_index = false;
    bool uses_stack_base = false;
    bool is_rip_relative = false;
    int scale = 1;
    bool has_memory_shape = parse_memory_operand_shape(
        insn,
        &has_index,
        &uses_stack_base,
        &is_rip_relative,
        &scale
    );
    if (uses_stack_base) return MVS_SCOPE_STACK;
    if (is_rip_relative) return MVS_SCOPE_GLOBAL;
    if (has_index) return MVS_SCOPE_ARRAY;

    if (!insn || insn->code_len == 0 || access_size < 8) return MVS_SCOPE_NORMAL;
    size_t pos = 0;
    while (pos < insn->code_len) {
        uint8_t byte = insn->code[pos];
        if (byte == 0x66 || byte == 0x67 || byte == 0xF0 || byte == 0xF2 || byte == 0xF3) {
            pos++;
            continue;
        }
        if ((byte & 0xF0) == 0x40) {
            pos++;
            continue;
        }
        break;
    }
    if (pos >= insn->code_len) return has_memory_shape ? MVS_SCOPE_POINTER : MVS_SCOPE_NORMAL;
    uint8_t opcode = insn->code[pos];
    if (opcode == 0x8B || opcode == 0xA1) return MVS_SCOPE_POINTER;
    return has_memory_shape ? MVS_SCOPE_POINTER : MVS_SCOPE_NORMAL;
}

static uint64_t scope_region_offset(MvsSeedScope scope) {
    switch (scope) {
        case MVS_SCOPE_POINTER: return 0x000000000000ULL;
        case MVS_SCOPE_STACK: return 0x010000000000ULL;
        case MVS_SCOPE_GLOBAL: return 0x020000000000ULL;
        case MVS_SCOPE_ARRAY: return 0x030000000000ULL;
        case MVS_SCOPE_NORMAL:
        default: return 0x1000000000ULL;
    }
}

static uint64_t choose_mvs_step(Ctx *ctx, MvsSeedScope scope, int access_size) {
    uint64_t default_padding = ctx->mvs_padding ? ctx->mvs_padding : 64;
    uint64_t access_width = access_size > 0 ? align_up((uint64_t)access_size, 8) : 8;
    switch (scope) {
        case MVS_SCOPE_STACK:
            return 0;
        case MVS_SCOPE_GLOBAL:
            return 0;
        case MVS_SCOPE_ARRAY:
            return access_width > default_padding ? access_width : default_padding;
        case MVS_SCOPE_POINTER:
            return default_padding;
        case MVS_SCOPE_NORMAL:
        default:
            return 0;
    }
}

static uint64_t mvs_seed_value(Ctx *ctx, uint64_t pc, uint64_t addr, int size) {
    if (!ctx || !ctx->mvs_enable) return 0;

    uint64_t scope_value = 0;
    if (!map_get(&ctx->mvs_pc_scope, pc, &scope_value)) {
        scope_value = (uint64_t)classify_mvs_seed_scope(ctx->cur_insn, size);
        map_put(&ctx->mvs_pc_scope, pc, scope_value);
    }
    MvsSeedScope scope = (MvsSeedScope)scope_value;
    uint64_t lines = ctx->mvs_limit_lines ? ctx->mvs_limit_lines : (1ULL << 20);
    uint64_t window_bytes = lines << 6;

    if (scope == MVS_SCOPE_NORMAL) {
        uint64_t normal_base = ctx->mvs_bound + scope_region_offset(scope);
        uint64_t v = normal_base + ((rng_next_u64(&ctx->rng_state) % lines) << 6) + (addr & 0x38ULL);
        ctx->mvs_seeded_normal++;
        return v;
    }

    uint64_t pc_base = 0;
    if (!map_get(&ctx->mvs_pc_base, pc, &pc_base)) {
        uint64_t region_base = ctx->mvs_bound + scope_region_offset(scope);
        uint64_t region_lines = lines ? lines : (1ULL << 20);
        uint64_t pc_hash = mix64(pc ^ ((uint64_t)scope << 56));
        uint64_t pc_line = pc_hash % region_lines;
        pc_base = region_base + (pc_line << 6);
        map_put(&ctx->mvs_pc_base, pc, pc_base);
    }

    uint64_t cursor = 0;
    if (!map_get(&ctx->mvs_pc_cursor, pc, &cursor)) {
        cursor = mix64(pc ^ addr ^ 0x6d76735f637572ULL) & 0x3F8ULL;
    }

    uint64_t step = 0;
    if (!map_get(&ctx->mvs_pc_step, pc, &step)) {
        step = choose_mvs_step(ctx, scope, size);
        if (scope == MVS_SCOPE_ARRAY && step < 8) step = 8;
        map_put(&ctx->mvs_pc_step, pc, step);
    }

    uint64_t disp_hint = addr & 0x38ULL;
    uint64_t line_off = window_bytes ? (cursor % window_bytes) : cursor;
    uint64_t v = pc_base + line_off + disp_hint;

    if (window_bytes) cursor = (cursor + step) % window_bytes;
    else cursor += step;
    map_put(&ctx->mvs_pc_cursor, pc, cursor);

    if (scope == MVS_SCOPE_POINTER || scope == MVS_SCOPE_ARRAY) ctx->mvs_seeded_indirect++;
    else ctx->mvs_seeded_normal++;
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

