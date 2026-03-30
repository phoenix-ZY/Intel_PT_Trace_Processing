#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trace_feature_core.h"

typedef struct {
    uint32_t tid;
    uint64_t insn_idx;
    uint64_t last_ginsn;
    uint64_t last_ip;
    bool has_insn;
} TidState;

typedef struct {
    TidState *arr;
    size_t n;
    size_t cap;
} TidTable;

typedef struct {
    const char *input_path;
    const char *mem_out_path;
    const char *insn_out_path;
    const char *inst_analysis_path;
    const char *data_analysis_path;
    uint64_t analysis_line_size;
    bool split_crossline;
    uint64_t analysis_sdp_max_lines;
    bool analysis_stack_depth;
    uint64_t analysis_rd_hist_cap_lines;
    uint64_t analysis_stride_bin_cap_lines;
} Opts;

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(2);
}

static uint64_t parse_u64_any(const char *s) {
    errno = 0;
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 0);
    if (errno || end == s || *end != '\0') die("invalid integer argument");
    return v;
}

static TidState *tid_table_get_or_create(TidTable *t, uint32_t tid) {
    for (size_t i = 0; i < t->n; i++) {
        if (t->arr[i].tid == tid) return &t->arr[i];
    }
    if (t->n == t->cap) {
        size_t ncap = (t->cap == 0) ? 8 : (t->cap * 2);
        TidState *na = (TidState *)realloc(t->arr, ncap * sizeof(TidState));
        if (!na) return NULL;
        t->arr = na;
        t->cap = ncap;
    }
    TidState *s = &t->arr[t->n++];
    s->tid = tid;
    s->insn_idx = 0;
    s->last_ginsn = 0;
    s->last_ip = 0;
    s->has_insn = false;
    return s;
}

static void usage(const char *prog) {
    fprintf(
        stderr,
        "Usage: %s -i SDE_DEBUGTRACE [options]\n"
        "Options:\n"
        "  --mem-out PATH           optional output data mem JSONL\n"
        "  --insn-out PATH          optional output insn trace text\n"
        "  --inst-analysis-out PATH optional instruction analysis JSON output\n"
        "  --data-analysis-out PATH optional data analysis JSON output\n"
        "  --analysis-line-size N   default 64\n"
        "  --split-crossline on|off default on (split memory ops spanning multiple cache lines)\n"
        "  --analysis-sdp-max-lines N default 262144\n"
        "  --analysis-rd-definition stack_depth|distinct_since_last (default stack_depth)\n"
        "  --analysis-rd-hist-cap-lines N default 262144 (0 disables cap)\n"
        "  --analysis-stride-bin-cap-lines N default 262144 (0 disables cap)\n",
        prog
    );
}

static void write_spaced_raw_bytes(FILE *f, const char *raw) {
    size_t n = strlen(raw);
    if (n % 2 != 0) n--;
    for (size_t i = 0; i + 1 < n; i += 2) {
        if (i) fputc(' ', f);
        fputc(raw[i], f);
        fputc(raw[i + 1], f);
    }
}

static bool parse_tid_prefix(const char **pp, uint32_t *tid) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    if (p[0] == 'T' && p[1] == 'I' && p[2] == 'D') {
        p += 3;
        if (!isdigit((unsigned char)*p)) return false;
        errno = 0;
        char *end = NULL;
        uint64_t t = strtoull(p, &end, 10);
        if (errno || end == p || *end != ':') return false;
        p = end + 1;
        while (*p == ' ' || *p == '\t') p++;
        *tid = (uint32_t)t;
        *pp = p;
        return true;
    }
    *tid = 0;
    *pp = p;
    return true;
}

static bool parse_uint_bits_and_addr(const char *line, int *bits, uint64_t *addr) {
    const char *u = strstr(line, "*(UINT");
    if (!u) return false;
    u += 6;
    if (!isdigit((unsigned char)*u)) return false;
    errno = 0;
    char *end = NULL;
    uint64_t b = strtoull(u, &end, 10);
    if (errno || end == u) return false;
    const char *a = strstr(end, "*)0x");
    if (!a) return false;
    a += 4;
    errno = 0;
    uint64_t v = strtoull(a, &end, 16);
    if (errno || end == a) return false;
    *bits = (int)b;
    *addr = v;
    return true;
}

static bool parse_ins_line(const char *line, uint64_t *ip, char *raw_hex, size_t raw_cap, bool *has_raw) {
    if (strncmp(line, "INS ", 4) != 0) return false;
    const char *p = line + 4;
    while (*p == ' ' || *p == '\t') p++;
    if (!(p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))) return false;
    p += 2;
    errno = 0;
    char *end = NULL;
    uint64_t v = strtoull(p, &end, 16);
    if (errno || end == p) return false;
    *ip = v;
    *has_raw = false;
    raw_hex[0] = '\0';

    const char *lb = strchr(end, '[');
    if (!lb) return true;
    const char *rb = strchr(lb + 1, ']');
    if (!rb || rb <= lb + 1) return true;
    size_t n = (size_t)(rb - (lb + 1));
    if (n >= raw_cap) n = raw_cap - 1;
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        char c = lb[1 + i];
        if (!isxdigit((unsigned char)c)) break;
        raw_hex[j++] = c;
    }
    raw_hex[j] = '\0';
    *has_raw = (j >= 2);
    return true;
}

int main(int argc, char **argv) {
    Opts o = {
        .input_path = NULL,
        .mem_out_path = NULL,
        .insn_out_path = NULL,
        .inst_analysis_path = NULL,
        .data_analysis_path = NULL,
        .analysis_line_size = 64,
        .split_crossline = true,
        .analysis_sdp_max_lines = 262144,
        .analysis_stack_depth = true,
        .analysis_rd_hist_cap_lines = 262144,
        .analysis_stride_bin_cap_lines = 262144,
    };

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--input")) {
            if (++i >= argc) die("missing value for --input");
            o.input_path = argv[i];
        } else if (!strcmp(argv[i], "--mem-out")) {
            if (++i >= argc) die("missing value for --mem-out");
            o.mem_out_path = argv[i];
        } else if (!strcmp(argv[i], "--insn-out")) {
            if (++i >= argc) die("missing value for --insn-out");
            o.insn_out_path = argv[i];
        } else if (!strcmp(argv[i], "--inst-analysis-out")) {
            if (++i >= argc) die("missing value for --inst-analysis-out");
            o.inst_analysis_path = argv[i];
        } else if (!strcmp(argv[i], "--data-analysis-out")) {
            if (++i >= argc) die("missing value for --data-analysis-out");
            o.data_analysis_path = argv[i];
        } else if (!strcmp(argv[i], "--analysis-line-size")) {
            if (++i >= argc) die("missing value for --analysis-line-size");
            o.analysis_line_size = parse_u64_any(argv[i]);
        } else if (!strcmp(argv[i], "--split-crossline")) {
            if (++i >= argc) die("missing value for --split-crossline");
            if (!strcmp(argv[i], "on")) o.split_crossline = true;
            else if (!strcmp(argv[i], "off")) o.split_crossline = false;
            else die("invalid --split-crossline (use on|off)");
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

    if (!o.input_path) die("input required");
    if (!o.mem_out_path && !o.insn_out_path && !o.inst_analysis_path && !o.data_analysis_path) {
        die("at least one output must be set");
    }
    if (o.analysis_line_size == 0 || (o.analysis_line_size & (o.analysis_line_size - 1)) != 0) {
        die("analysis-line-size must be a positive power of two");
    }
    if (o.analysis_sdp_max_lines == 0) die("analysis-sdp-max-lines must be > 0");

    FILE *fin = fopen(o.input_path, "r");
    if (!fin) die("failed to open input");
    FILE *fmem = NULL;
    FILE *finsn = NULL;
    if (o.mem_out_path) {
        fmem = fopen(o.mem_out_path, "w");
        if (!fmem) die("failed to open mem-out");
    }
    if (o.insn_out_path) {
        finsn = fopen(o.insn_out_path, "w");
        if (!finsn) die("failed to open insn-out");
    }

    TfProfile *inst_prof = NULL;
    TfProfile *data_prof = NULL;
    if (o.inst_analysis_path) {
        inst_prof = tf_profile_create(false, o.analysis_line_size, o.analysis_stack_depth);
        if (!inst_prof) die("oom inst profile");
    }
    if (o.data_analysis_path) {
        data_prof = tf_profile_create(false, o.analysis_line_size, o.analysis_stack_depth);
        if (!data_prof) die("oom data profile");
    }

    TidTable tt = {0};
    uint64_t global_insn = 0;
    bool has_any_insn = false;
    uint64_t mem_events = 0, insn_events = 0, insn_with_raw = 0;

    char line[8192];
    while (fgets(line, sizeof(line), fin)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        const char *p = line;
        uint32_t tid = 0;
        if (!parse_tid_prefix(&p, &tid)) continue;

        TidState *st = tid_table_get_or_create(&tt, tid);
        if (!st) die("oom tid table");

        if (!strncmp(p, "Read ", 5) || !strncmp(p, "Write ", 6)) {
            int bits = 0;
            uint64_t addr = 0;
            if (!parse_uint_bits_and_addr(p, &bits, &addr)) continue;
            int size = bits / 8;
            if (size <= 0) size = 1;
            if (fmem) {
                int64_t insn_idx = st->has_insn ? (int64_t)st->insn_idx : -1;
                int64_t ginsn = st->has_insn ? (int64_t)st->last_ginsn : -1;
                fprintf(
                    fmem,
                    "{\"access\":\"%s\",\"addr\":\"0x%" PRIx64 "\",\"size\":%d,\"tid\":%u,"
                    "\"insn_idx\":%" PRId64 ",\"ginsn\":%" PRId64 "}\n",
                    (!strncmp(p, "Write ", 6)) ? "write" : "read",
                    addr,
                    size,
                    tid,
                    insn_idx,
                    ginsn
                );
            }
            if (data_prof) {
                TfAccessKind ak = (!strncmp(p, "Write ", 6)) ? TF_ACCESS_WRITE : TF_ACCESS_READ;
                if (!o.split_crossline ||
                    ((addr & (o.analysis_line_size - 1)) + (uint64_t)size <= o.analysis_line_size)) {
                    tf_profile_add_data(data_prof, tid, addr, st->has_insn ? st->last_ip : 0, ak);
                } else {
                    uint64_t start = addr / o.analysis_line_size;
                    uint64_t end = (addr + (uint64_t)size - 1) / o.analysis_line_size;
                    for (uint64_t ln = start; ln <= end; ln++) {
                        uint64_t line_addr = ln * o.analysis_line_size;
                        tf_profile_add_data(data_prof, tid, line_addr, st->has_insn ? st->last_ip : 0, ak);
                    }
                }
            }
            mem_events++;
            continue;
        }

        uint64_t ip = 0;
        char raw_hex[2 * 32 + 1];
        bool has_raw = false;
        if (parse_ins_line(p, &ip, raw_hex, sizeof(raw_hex), &has_raw)) {
            has_any_insn = true;
            if (!st->has_insn) st->insn_idx = 0;
            else st->insn_idx += 1;
            st->has_insn = true;
            st->last_ginsn = global_insn;
            st->last_ip = ip;
            global_insn++;
            insn_events++;
            if (has_raw) {
                if (finsn) {
                    fprintf(finsn, "%u 0.0: %" PRIx64 " insn: ", tid, ip);
                    write_spaced_raw_bytes(finsn, raw_hex);
                    fputc('\n', finsn);
                }
                if (inst_prof) tf_profile_add_inst(inst_prof, tid, ip);
                insn_with_raw++;
            }
            continue;
        }
    }

    if (o.inst_analysis_path && inst_prof) {
        FILE *fa = fopen(o.inst_analysis_path, "w");
        if (!fa) die("failed to open inst-analysis-out");
        tf_profile_write_analysis_json(
            fa,
            inst_prof,
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
    if (o.data_analysis_path && data_prof) {
        FILE *fa = fopen(o.data_analysis_path, "w");
        if (!fa) die("failed to open data-analysis-out");
        tf_profile_write_analysis_json(
            fa,
            data_prof,
            "data",
            "mem_jsonl",
            o.input_path,
            o.analysis_line_size,
            o.analysis_stack_depth ? "stack_depth" : "distinct_since_last",
            o.analysis_sdp_max_lines,
            o.analysis_rd_hist_cap_lines,
            o.analysis_stride_bin_cap_lines
        );
        fclose(fa);
    }

    fprintf(stderr, "done: insns=%" PRIu64 " insn_with_raw=%" PRIu64 " mem_events=%" PRIu64 "\n", insn_events, insn_with_raw, mem_events);
    if (has_any_insn && insn_with_raw == 0) {
        fprintf(stderr, "warning: no raw bytes in INS lines; insn-out/inst-analysis may be empty\n");
    }

    free(tt.arr);
    tf_profile_destroy(inst_prof);
    tf_profile_destroy(data_prof);
    if (fmem) fclose(fmem);
    if (finsn) fclose(finsn);
    fclose(fin);
    return 0;
}
