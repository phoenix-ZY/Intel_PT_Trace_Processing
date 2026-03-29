#ifndef TRACE_FEATURE_CORE_H
#define TRACE_FEATURE_CORE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    TF_ACCESS_READ = 0,
    TF_ACCESS_WRITE = 1,
} TfAccessKind;

typedef struct TfStream TfStream;

typedef struct {
    TfStream *all;
    TfStream *read;
    TfStream *write;
    bool with_rw;
} TfProfile;

TfProfile *tf_profile_create(bool with_rw, uint64_t line_size, bool rd_stack_depth);
void tf_profile_destroy(TfProfile *p);

void tf_profile_add_inst(TfProfile *p, uint32_t tid, uint64_t ip);
void tf_profile_add_data(TfProfile *p, uint32_t tid, uint64_t addr, TfAccessKind kind);

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
);

#endif
