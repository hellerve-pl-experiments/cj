#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void (*cj_fn)(void);

typedef struct
{
  int id;
} cj_label;

typedef enum
{
  CJ_FIXUP_KIND_ARM_BRANCH,
  CJ_FIXUP_KIND_X86_RELATIVE
} cj_fixup_kind;

typedef struct
{
  int label_id;
  uint64_t patch_offset;
  cj_fixup_kind kind;
  union
  {
    struct
    {
      uint8_t offset_bits;
      uint8_t offset_shift;
    } arm;
    struct
    {
      uint8_t width;
    } x86;
  } info;
} cj_fixup;

typedef struct
{
  uint8_t *mem;
  uint64_t len;
  uint64_t size;

  uint64_t *label_positions;
  int num_labels;
  int label_capacity;

  cj_fixup *fixups;
  int num_fixups;
  int fixup_capacity;

  uint8_t *executable_base;
  uint8_t *executable_raw;
  size_t executable_size;
  uint64_t executable_code_size;
} cj_ctx;

cj_ctx *create_cj_ctx(void);
void cj_add_u8(cj_ctx *, uint8_t);
void cj_add_u16(cj_ctx *, uint16_t);
void cj_add_u32(cj_ctx *, uint32_t);
void cj_add_u64(cj_ctx *, uint64_t);
void cj_add_bytes(cj_ctx *, uint8_t *, uint64_t);
void destroy_cj_ctx(cj_ctx *);
cj_fn create_cj_fn(cj_ctx *);
void destroy_cj_fn(cj_ctx *, cj_fn);

cj_label cj_create_label(cj_ctx *ctx);
void cj_mark_label(cj_ctx *ctx, cj_label label);

void cj_emit_branch(cj_ctx *ctx, uint32_t base_instr, cj_label label, uint8_t offset_bits,
                    uint8_t offset_shift);
void cj_emit_x86_rel(cj_ctx *ctx, const uint8_t *opcode, size_t opcode_len, uint8_t disp_width,
                     cj_label label);
void *cj_resolve_label(const cj_ctx *ctx, cj_fn module, cj_label label);
