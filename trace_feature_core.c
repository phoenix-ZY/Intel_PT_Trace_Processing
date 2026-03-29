#include "trace_feature_core.h"

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t *keys;
    uint64_t *vals;
    uint8_t *used;
    size_t cap;
    size_t sz;
} TfMap;

typedef struct {
    int64_t *bit;
    size_t cap;
} TfFenwick;

struct TfStream {
    uint64_t line_size;
    bool rd_stack_depth;
    uint64_t events;
    uint64_t cold;
    uint64_t reuses;
    uint64_t active_total;
    TfMap last_pos_by_line;
    TfMap prev_line_by_tid;
    TfMap rd_hist;
    TfMap delta_hist; // key = int64 encoded with sign bit xor
    TfFenwick fw;
};

static uint64_t tf_mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static uint64_t enc_i64(int64_t v) { return ((uint64_t)v) ^ 0x8000000000000000ULL; }
static int64_t dec_i64(uint64_t v) { return (int64_t)(v ^ 0x8000000000000000ULL); }

static void tf_map_init(TfMap *m, size_t cap_pow2) {
    m->cap = cap_pow2;
    m->sz = 0;
    m->keys = (uint64_t *)calloc(cap_pow2, sizeof(uint64_t));
    m->vals = (uint64_t *)calloc(cap_pow2, sizeof(uint64_t));
    m->used = (uint8_t *)calloc(cap_pow2, sizeof(uint8_t));
}

static void tf_map_free(TfMap *m) {
    free(m->keys);
    free(m->vals);
    free(m->used);
    memset(m, 0, sizeof(*m));
}

static void tf_map_rehash(TfMap *m) {
    TfMap n;
    tf_map_init(&n, m->cap << 1);
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->used[i]) continue;
        uint64_t k = m->keys[i], v = m->vals[i];
        size_t p = (size_t)(tf_mix64(k) & (n.cap - 1));
        while (n.used[p]) p = (p + 1) & (n.cap - 1);
        n.used[p] = 1;
        n.keys[p] = k;
        n.vals[p] = v;
        n.sz++;
    }
    tf_map_free(m);
    *m = n;
}

static bool tf_map_get(const TfMap *m, uint64_t k, uint64_t *out) {
    size_t p = (size_t)(tf_mix64(k) & (m->cap - 1));
    while (m->used[p]) {
        if (m->keys[p] == k) {
            *out = m->vals[p];
            return true;
        }
        p = (p + 1) & (m->cap - 1);
    }
    return false;
}

static void tf_map_put(TfMap *m, uint64_t k, uint64_t v) {
    if ((m->sz + 1) * 10 >= m->cap * 7) tf_map_rehash(m);
    size_t p = (size_t)(tf_mix64(k) & (m->cap - 1));
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

static void tf_map_inc(TfMap *m, uint64_t k, uint64_t inc) {
    if ((m->sz + 1) * 10 >= m->cap * 7) tf_map_rehash(m);
    size_t p = (size_t)(tf_mix64(k) & (m->cap - 1));
    while (m->used[p]) {
        if (m->keys[p] == k) {
            m->vals[p] += inc;
            return;
        }
        p = (p + 1) & (m->cap - 1);
    }
    m->used[p] = 1;
    m->keys[p] = k;
    m->vals[p] = inc;
    m->sz++;
}

static void tf_fw_init(TfFenwick *fw) {
    fw->cap = 0;
    fw->bit = NULL;
}

static void tf_fw_free(TfFenwick *fw) {
    free(fw->bit);
    fw->bit = NULL;
    fw->cap = 0;
}

static void tf_fw_reserve(TfFenwick *fw, size_t idx) {
    if (idx <= fw->cap) return;
    size_t ncap = fw->cap ? fw->cap : 1024;
    while (ncap < idx) ncap <<= 1;
    int64_t *nb = (int64_t *)calloc(ncap + 1, sizeof(int64_t));
    if (!nb) return;
    if (fw->bit) {
        // Rebuild Fenwick tree values when capacity grows.
        // A plain memcpy is incorrect because old updates were never propagated
        // to parent nodes that only exist in the larger-capacity tree.
        size_t oldcap = fw->cap;
        int64_t *ob = fw->bit;
        for (size_t i = 1; i <= oldcap; i++) {
            int64_t s1 = 0, s0 = 0;
            for (size_t p = i; p > 0; p -= p & (~p + 1)) s1 += ob[p];
            for (size_t p = i - 1; p > 0; p -= p & (~p + 1)) s0 += ob[p];
            int64_t point = s1 - s0;
            if (point == 0) continue;
            for (size_t j = i; j <= ncap; j += j & (~j + 1)) nb[j] += point;
        }
        free(fw->bit);
    }
    fw->bit = nb;
    fw->cap = ncap;
}

static void tf_fw_add(TfFenwick *fw, size_t idx, int delta) {
    if (idx == 0) return;
    tf_fw_reserve(fw, idx);
    for (size_t i = idx; i <= fw->cap; i += i & (~i + 1)) fw->bit[i] += delta;
}

static uint64_t tf_fw_sum(const TfFenwick *fw, size_t idx) {
    if (idx > fw->cap) idx = fw->cap;
    int64_t s = 0;
    for (size_t i = idx; i > 0; i -= i & (~i + 1)) s += fw->bit[i];
    return (s < 0) ? 0 : (uint64_t)s;
}

static TfStream *tf_stream_create(uint64_t line_size, bool rd_stack_depth) {
    TfStream *s = (TfStream *)calloc(1, sizeof(TfStream));
    if (!s) return NULL;
    s->line_size = line_size;
    s->rd_stack_depth = rd_stack_depth;
    tf_map_init(&s->last_pos_by_line, 1 << 16);
    tf_map_init(&s->prev_line_by_tid, 1 << 12);
    tf_map_init(&s->rd_hist, 1 << 12);
    tf_map_init(&s->delta_hist, 1 << 12);
    tf_fw_init(&s->fw);
    return s;
}

static void tf_stream_destroy(TfStream *s) {
    if (!s) return;
    tf_map_free(&s->last_pos_by_line);
    tf_map_free(&s->prev_line_by_tid);
    tf_map_free(&s->rd_hist);
    tf_map_free(&s->delta_hist);
    tf_fw_free(&s->fw);
    free(s);
}

static int64_t tf_delta_lines(uint64_t cur, uint64_t prev) {
    if (cur >= prev) {
        uint64_t d = cur - prev;
        if (d > (uint64_t)INT64_MAX) return INT64_MAX;
        return (int64_t)d;
    }
    uint64_t d = prev - cur;
    if (d > (uint64_t)INT64_MAX) return INT64_MIN + 1;
    return -(int64_t)d;
}

static void tf_stream_add(TfStream *s, uint32_t tid, uint64_t addr) {
    uint64_t line = (s->line_size == 0) ? addr : (addr / s->line_size);

    uint64_t prev_line = 0;
    if (tf_map_get(&s->prev_line_by_tid, (uint64_t)tid, &prev_line)) {
        int64_t d = tf_delta_lines(line, prev_line);
        tf_map_inc(&s->delta_hist, enc_i64(d), 1);
    }
    tf_map_put(&s->prev_line_by_tid, (uint64_t)tid, line);

    s->events++;
    uint64_t pos = s->events;
    uint64_t prev_pos = 0;
    if (tf_map_get(&s->last_pos_by_line, line, &prev_pos)) {
        uint64_t distinct_since_last = s->active_total - tf_fw_sum(&s->fw, (size_t)prev_pos);
        uint64_t rd = s->rd_stack_depth ? (distinct_since_last + 1) : distinct_since_last;
        tf_map_inc(&s->rd_hist, rd, 1);
        s->reuses++;
        tf_fw_add(&s->fw, (size_t)prev_pos, -1);
    } else {
        s->cold++;
        s->active_total++;
    }
    tf_fw_add(&s->fw, (size_t)pos, +1);
    tf_map_put(&s->last_pos_by_line, line, pos);
}

TfProfile *tf_profile_create(bool with_rw, uint64_t line_size, bool rd_stack_depth) {
    TfProfile *p = (TfProfile *)calloc(1, sizeof(TfProfile));
    if (!p) return NULL;
    p->all = tf_stream_create(line_size, rd_stack_depth);
    if (!p->all) {
        free(p);
        return NULL;
    }
    p->with_rw = with_rw;
    if (with_rw) {
        p->read = tf_stream_create(line_size, rd_stack_depth);
        p->write = tf_stream_create(line_size, rd_stack_depth);
        if (!p->read || !p->write) {
            tf_stream_destroy(p->all);
            tf_stream_destroy(p->read);
            tf_stream_destroy(p->write);
            free(p);
            return NULL;
        }
    }
    return p;
}

void tf_profile_destroy(TfProfile *p) {
    if (!p) return;
    tf_stream_destroy(p->all);
    tf_stream_destroy(p->read);
    tf_stream_destroy(p->write);
    free(p);
}

void tf_profile_add_inst(TfProfile *p, uint32_t tid, uint64_t ip) {
    if (!p || !p->all) return;
    tf_stream_add(p->all, tid, ip);
}

void tf_profile_add_data(TfProfile *p, uint32_t tid, uint64_t addr, TfAccessKind kind) {
    if (!p || !p->all) return;
    tf_stream_add(p->all, tid, addr);
    if (p->with_rw) {
        if (kind == TF_ACCESS_READ && p->read) tf_stream_add(p->read, tid, addr);
        if (kind == TF_ACCESS_WRITE && p->write) tf_stream_add(p->write, tid, addr);
    }
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y);
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x < y) ? -1 : (x > y);
}

static void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') {
            fputc('\\', f);
            fputc(*s, f);
        } else if ((unsigned char)*s < 0x20) {
            fprintf(f, "\\u%04x", (unsigned char)*s);
        } else {
            fputc(*s, f);
        }
    }
    fputc('"', f);
}

static void write_rd_hist(FILE *f, const TfMap *hist, int indent, uint64_t rd_hist_cap_lines) {
    if (rd_hist_cap_lines > 0) {
        TfMap merged;
        tf_map_init(&merged, 1 << 12);
        for (size_t i = 0; i < hist->cap; i++) {
            if (!hist->used[i]) continue;
            uint64_t k = hist->keys[i];
            if (k > rd_hist_cap_lines) k = rd_hist_cap_lines;
            tf_map_inc(&merged, k, hist->vals[i]);
        }
        write_rd_hist(f, &merged, indent, 0);
        tf_map_free(&merged);
        return;
    }
    size_t n = hist->sz;
    uint64_t *keys = (uint64_t *)malloc(n * sizeof(uint64_t));
    size_t j = 0;
    for (size_t i = 0; i < hist->cap; i++) if (hist->used[i]) keys[j++] = hist->keys[i];
    qsort(keys, n, sizeof(uint64_t), cmp_u64);
    fprintf(f, "{");
    for (size_t i = 0; i < n; i++) {
        uint64_t v = 0;
        tf_map_get(hist, keys[i], &v);
        if (i) fprintf(f, ",");
        fprintf(f, "\n%*s\"%" PRIu64 "\": %" PRIu64, indent, "", keys[i], v);
    }
    if (n) fprintf(f, "\n%*s", indent - 2, "");
    fprintf(f, "}");
    free(keys);
}

static void write_delta_hist(FILE *f, const TfMap *hist, int indent) {
    size_t n = hist->sz;
    int64_t *keys = (int64_t *)malloc(n * sizeof(int64_t));
    size_t j = 0;
    for (size_t i = 0; i < hist->cap; i++) if (hist->used[i]) keys[j++] = dec_i64(hist->keys[i]);
    qsort(keys, n, sizeof(int64_t), cmp_i64);
    fprintf(f, "{");
    for (size_t i = 0; i < n; i++) {
        uint64_t v = 0;
        tf_map_get(hist, enc_i64(keys[i]), &v);
        if (i) fprintf(f, ",");
        fprintf(f, "\n%*s\"%" PRId64 "\": %" PRIu64, indent, "", keys[i], v);
    }
    if (n) fprintf(f, "\n%*s", indent - 2, "");
    fprintf(f, "}");
    free(keys);
}

static void write_sdp(FILE *f, const TfStream *s, uint64_t sdp_max_lines, int indent) {
    uint64_t max_rd = 1;
    size_t n = s->rd_hist.sz;
    uint64_t *keys = (uint64_t *)malloc(n * sizeof(uint64_t));
    size_t j = 0;
    for (size_t i = 0; i < s->rd_hist.cap; i++) {
        if (!s->rd_hist.used[i]) continue;
        keys[j++] = s->rd_hist.keys[i];
        if (s->rd_hist.keys[i] > max_rd) max_rd = s->rd_hist.keys[i];
    }
    qsort(keys, n, sizeof(uint64_t), cmp_u64);

    uint64_t cap_upper = max_rd;
    if (cap_upper > sdp_max_lines) cap_upper = sdp_max_lines;
    if (cap_upper < 1) cap_upper = 1;

    uint64_t caps[128];
    size_t cc = 0;
    uint64_t c = 1;
    while (c <= cap_upper && cc < 128) {
        caps[cc++] = c;
        c <<= 1;
    }
    if (cc == 0 || caps[cc - 1] != cap_upper) caps[cc++] = cap_upper;

    fprintf(f, "{\n%*s\"capacities_lines\": [", indent, "");
    for (size_t i = 0; i < cc; i++) {
        if (i) fprintf(f, ", ");
        fprintf(f, "%" PRIu64, caps[i]);
    }
    fprintf(f, "],\n%*s\"miss_ratio\": [", indent, "");
    uint64_t idx = 0, hits = 0;
    for (size_t i = 0; i < cc; i++) {
        while (idx < n && keys[idx] <= caps[i]) {
            uint64_t cnt = 0;
            tf_map_get(&s->rd_hist, keys[idx], &cnt);
            hits += cnt;
            idx++;
        }
        double miss = 0.0;
        if (s->events > 0) {
            miss = 1.0 - ((double)(s->cold + hits) / (double)s->events);
            if (miss < 0.0) miss = 0.0;
        }
        if (i) fprintf(f, ", ");
        fprintf(f, "%.10g", miss);
    }
    fprintf(f, "]\n%*s}", indent - 2, "");
    free(keys);
}

static void write_stride_abs_bucket_hist(FILE *f, const TfMap *delta_hist, int indent, uint64_t stride_bin_cap_lines) {
    TfMap b;
    tf_map_init(&b, 1 << 8);
    uint64_t over_cap_cnt = 0;
    for (size_t i = 0; i < delta_hist->cap; i++) {
        if (!delta_hist->used[i]) continue;
        int64_t d = dec_i64(delta_hist->keys[i]);
        uint64_t cnt = delta_hist->vals[i];
        uint64_t a = (d < 0) ? (uint64_t)(-(d + 1)) + 1 : (uint64_t)d;
        if (stride_bin_cap_lines > 0 && a > stride_bin_cap_lines) {
            over_cap_cnt += cnt;
            continue;
        }
        uint64_t key = 0;
        if (a == 0) key = 0;
        else if (a == 1) key = 1;
        else {
            int bidx = 63 - __builtin_clzll(a);
            key = 1ULL << bidx;
        }
        tf_map_inc(&b, key, cnt);
    }
    size_t n = b.sz;
    uint64_t *keys = (uint64_t *)malloc(n * sizeof(uint64_t));
    size_t j = 0;
    for (size_t i = 0; i < b.cap; i++) if (b.used[i]) keys[j++] = b.keys[i];
    qsort(keys, n, sizeof(uint64_t), cmp_u64);
    fprintf(f, "{");
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        uint64_t cnt = 0;
        tf_map_get(&b, keys[i], &cnt);
        if (!first) fprintf(f, ",");
        first = false;
        if (keys[i] == 0) fprintf(f, "\n%*s\"0\": %" PRIu64, indent, "", cnt);
        else if (keys[i] == 1) fprintf(f, "\n%*s\"1\": %" PRIu64, indent, "", cnt);
        else fprintf(f, "\n%*s\"%" PRIu64 "-%" PRIu64 "\": %" PRIu64, indent, "", keys[i], (keys[i] << 1) - 1, cnt);
    }
    if (over_cap_cnt > 0 && stride_bin_cap_lines > 0) {
        if (!first) fprintf(f, ",");
        fprintf(f, "\n%*s\">=%" PRIu64 "\": %" PRIu64, indent, "", stride_bin_cap_lines, over_cap_cnt);
        first = false;
    }
    if (!first) fprintf(f, "\n%*s", indent - 2, "");
    fprintf(f, "}");
    free(keys);
    tf_map_free(&b);
}

static void write_stream_obj(
    FILE *f,
    const TfStream *s,
    uint64_t sdp_max_lines,
    int indent,
    uint64_t rd_hist_cap_lines,
    uint64_t stride_bin_cap_lines
) {
    uint64_t d_total = 0, z = 0, near = 0;
    for (size_t i = 0; i < s->delta_hist.cap; i++) {
        if (!s->delta_hist.used[i]) continue;
        int64_t d = dec_i64(s->delta_hist.keys[i]);
        uint64_t c = s->delta_hist.vals[i];
        d_total += c;
        if (d == 0) z += c;
        if (d >= -1 && d <= 1) near += c;
    }
    double cold_ratio = (s->events > 0) ? ((double)s->cold / (double)s->events) : 0.0;
    double zr = (d_total > 0) ? ((double)z / (double)d_total) : 0.0;
    double nr = (d_total > 0) ? ((double)near / (double)d_total) : 0.0;
    fprintf(f, "{\n");
    fprintf(f, "%*s\"events\": %" PRIu64 ",\n", indent, "", s->events);
    fprintf(f, "%*s\"cold\": %" PRIu64 ",\n", indent, "", s->cold);
    fprintf(f, "%*s\"reuses\": %" PRIu64 ",\n", indent, "", s->reuses);
    fprintf(f, "%*s\"cold_ratio\": %.10g,\n", indent, "", cold_ratio);
    fprintf(f, "%*s\"rd_histogram\": ", indent, "");
    write_rd_hist(f, &s->rd_hist, indent + 2, rd_hist_cap_lines);
    fprintf(f, ",\n%*s\"sdp\": ", indent, "");
    write_sdp(f, s, sdp_max_lines, indent + 2);
    fprintf(f, ",\n%*s\"stride\": {\n", indent, "");
    fprintf(f, "%*s\"delta_histogram\": ", indent + 2, "");
    write_delta_hist(f, &s->delta_hist, indent + 4);
    fprintf(f, ",\n%*s\"abs_delta_bucket_histogram\": ", indent + 2, "");
    write_stride_abs_bucket_hist(f, &s->delta_hist, indent + 4, stride_bin_cap_lines);
    fprintf(f, ",\n%*s\"zero_delta_ratio\": %.10g,\n", indent + 2, "", zr);
    fprintf(f, "%*s\"nearby_delta_ratio_abs_le_1\": %.10g\n", indent + 2, "", nr);
    fprintf(f, "%*s}\n", indent, "");
    fprintf(f, "%*s}", indent - 2, "");
}

int tf_profile_write_analysis_json(
    FILE *out,
    const TfProfile *p,
    const char *trace_kind,
    const char *input_format,
    const char *input_path,
    uint64_t line_size,
    const char *rd_definition,
    uint64_t sdp_max_lines,
    uint64_t rd_hist_cap_lines,
    uint64_t stride_bin_cap_lines
) {
    if (!out || !p || !p->all) return -1;
    fprintf(out, "{\n");
    fprintf(out, "  \"line_size\": %" PRIu64 ",\n", line_size);
    fprintf(out, "  \"rd_definition\": ");
    json_escape(out, rd_definition ? rd_definition : "stack_depth");
    fprintf(out, ",\n");
    fprintf(out, "  \"rd_hist_cap_lines\": %" PRIu64 ",\n", rd_hist_cap_lines);
    fprintf(out, "  \"stride_bin_cap_lines\": %" PRIu64 ",\n", stride_bin_cap_lines);
    fprintf(out, "  \"trace_kind\": ");
    json_escape(out, trace_kind ? trace_kind : "data");
    fprintf(out, ",\n");
    fprintf(out, "  \"input_format\": ");
    json_escape(out, input_format ? input_format : "mem_jsonl");
    fprintf(out, ",\n");
    fprintf(out, "  \"input_path\": ");
    json_escape(out, input_path ? input_path : "");
    fprintf(out, ",\n");
    if (p->with_rw) fprintf(out, "  \"accesses\": [\"all\", \"read\", \"write\"],\n");
    else fprintf(out, "  \"accesses\": [\"all\"],\n");
    fprintf(out, "  \"per_access\": {\n");
    fprintf(out, "    \"all\": ");
    write_stream_obj(out, p->all, sdp_max_lines, 6, rd_hist_cap_lines, stride_bin_cap_lines);
    if (p->with_rw) {
        fprintf(out, ",\n    \"read\": ");
        write_stream_obj(out, p->read, sdp_max_lines, 6, rd_hist_cap_lines, stride_bin_cap_lines);
        fprintf(out, ",\n    \"write\": ");
        write_stream_obj(out, p->write, sdp_max_lines, 6, rd_hist_cap_lines, stride_bin_cap_lines);
        fprintf(out, "\n");
    } else {
        fprintf(out, "\n");
    }
    fprintf(out, "  }\n}\n");
    return 0;
}
