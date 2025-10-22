#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "ctx.h"

cj_ctx *create_cj_ctx(void)
{
  cj_ctx *res = malloc(sizeof(cj_ctx));
  res->mem = calloc(1, 32);
  res->len = 0;
  res->size = 32;

  res->label_capacity = 16;
  res->num_labels = 0;
  res->label_positions = malloc(sizeof(uint64_t) * res->label_capacity);

  res->fixup_capacity = 32;
  res->num_fixups = 0;
  res->fixups = malloc(sizeof(cj_fixup) * res->fixup_capacity);

  res->executable_base = NULL;
  res->executable_raw = NULL;
  res->executable_size = 0;
  res->executable_code_size = 0;

  return res;
}

void grow_cj_ctx(cj_ctx *ctx)
{
  if (!ctx) return;

  uint64_t old_size = ctx->size;
  uint64_t new_size = old_size * 2;
  if (new_size < old_size) return;

  uint8_t *new_mem = realloc(ctx->mem, new_size);
  if (!new_mem) return;

  ctx->mem = new_mem;
  memset(ctx->mem + old_size, 0, old_size);
  ctx->size = new_size;
}

void destroy_cj_ctx(cj_ctx *ctx)
{
  free(ctx->mem);
  free(ctx->label_positions);
  free(ctx->fixups);
  free(ctx);
}

cj_fn create_cj_fn(cj_ctx *ctx)
{
  if (!ctx->len) return NULL;

  uint64_t code_size = ctx->len;
  size_t total_size = sizeof(uint64_t) + (size_t)code_size;

  uint8_t *raw = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return NULL;

  assert(ctx->mem);
  uint8_t *dest = raw + sizeof(uint64_t);
  memcpy(dest, ctx->mem, code_size);
  *((uint64_t *)raw) = code_size;

  if (mprotect(raw, total_size, PROT_READ | PROT_EXEC) != 0)
  {
    munmap(raw, total_size);
    return NULL;
  }

  ctx->executable_raw = raw;
  ctx->executable_base = dest;
  ctx->executable_size = total_size;
  ctx->executable_code_size = code_size;

  // clear the I cache for ARM64
  __builtin___clear_cache((char *)raw, (char *)raw + total_size);

// we know this is unsafe, and we do it anywyy
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  return (cj_fn)(raw + sizeof(uint64_t));
#pragma GCC diagnostic pop
}

void destroy_cj_fn(cj_ctx *ctx, cj_fn mem)
{
  (void)ctx;
  if (!mem) return;

// yes, yes. unsafe. boo-hoo.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
  uint8_t *code = (uint8_t *)(void *)mem;
#pragma GCC diagnostic pop
  uint8_t *raw = code - sizeof(uint64_t);
  uint64_t code_size = *((uint64_t *)raw);
  size_t total_size = sizeof(uint64_t) + (size_t)code_size;

  munmap(raw, total_size);

  if (ctx)
  {
    ctx->executable_base = NULL;
    ctx->executable_raw = NULL;
    ctx->executable_size = 0;
    ctx->executable_code_size = 0;
  }
}

void cj_add_u8(cj_ctx *ctx, uint8_t byte)
{
  if (ctx->len >= ctx->size) grow_cj_ctx(ctx);

  ctx->mem[ctx->len++] = byte;
}

void cj_add_u16(cj_ctx *ctx, uint16_t b2)
{
  cj_add_u8(ctx, b2 & 0xff);
  cj_add_u8(ctx, (b2 >> 8) & 0xff);
}

void cj_add_u32(cj_ctx *ctx, uint32_t b4)
{
  cj_add_u16(ctx, b4 & 0xffff);
  cj_add_u16(ctx, (b4 >> 16) & 0xffff);
}

void cj_add_u64(cj_ctx *ctx, uint64_t b8)
{
  cj_add_u32(ctx, b8 & 0xffffffff);
  cj_add_u32(ctx, (b8 >> 32) & 0xffffffff);
}

void cj_add_bytes(cj_ctx *ctx, uint8_t *bytes, uint64_t len)
{
  for (uint64_t i = 0; i < len; i++) cj_add_u8(ctx, bytes[i]);
}

cj_label cj_create_label(cj_ctx *ctx)
{
  if (ctx->num_labels >= ctx->label_capacity)
  {
    ctx->label_capacity *= 2;
    ctx->label_positions = realloc(ctx->label_positions, sizeof(uint64_t) * ctx->label_capacity);
  }

  cj_label label = {.id = ctx->num_labels};
  ctx->label_positions[ctx->num_labels] = UINT64_MAX;
  ctx->num_labels++;

  return label;
}

void cj_mark_label(cj_ctx *ctx, cj_label label)
{
  if (label.id < 0 || label.id >= ctx->num_labels) return;

  ctx->label_positions[label.id] = ctx->len;

  for (int i = 0; i < ctx->num_fixups; i++)
  {
    if (ctx->fixups[i].label_id == label.id)
    {
      if (ctx->fixups[i].kind == CJ_FIXUP_KIND_ARM_BRANCH)
      {
        uint64_t instr_pos = ctx->fixups[i].patch_offset;
        int64_t byte_offset = (int64_t)ctx->label_positions[label.id] - (int64_t)instr_pos;
        int64_t instr_offset = byte_offset / 4;

        uint32_t instr = ctx->mem[instr_pos] | (ctx->mem[instr_pos + 1] << 8) |
                         (ctx->mem[instr_pos + 2] << 16) | (ctx->mem[instr_pos + 3] << 24);

        uint32_t offset_mask = ((1U << ctx->fixups[i].info.arm.offset_bits) - 1);
        instr &= ~(offset_mask << ctx->fixups[i].info.arm.offset_shift);
        instr |= (((uint32_t)instr_offset & offset_mask) << ctx->fixups[i].info.arm.offset_shift);

        ctx->mem[instr_pos] = instr & 0xFF;
        ctx->mem[instr_pos + 1] = (instr >> 8) & 0xFF;
        ctx->mem[instr_pos + 2] = (instr >> 16) & 0xFF;
        ctx->mem[instr_pos + 3] = (instr >> 24) & 0xFF;
      }
      else if (ctx->fixups[i].kind == CJ_FIXUP_KIND_X86_RELATIVE)
      {
        uint64_t disp_pos = ctx->fixups[i].patch_offset;
        uint8_t width = ctx->fixups[i].info.x86.width;
        int64_t rel = (int64_t)ctx->len - (int64_t)(disp_pos + width);

        int64_t min = -(1LL << ((width * 8) - 1));
        int64_t max = (1LL << ((width * 8) - 1)) - 1;
        if (rel < min || rel > max)
        {
          ctx->fixups[i].label_id = -1;
          continue;
        }

        for (uint8_t b = 0; b < width; b++)
        {
          ctx->mem[disp_pos + b] = (uint8_t)((rel >> (8 * b)) & 0xFF);
        }
      }
      ctx->fixups[i].label_id = -1;
    }
  }
}

void cj_emit_branch(cj_ctx *ctx, uint32_t base_instr, cj_label label, uint8_t offset_bits,
                    uint8_t offset_shift)
{
  uint64_t current_pos = ctx->len;

  if (label.id >= 0 && label.id < ctx->num_labels && ctx->label_positions[label.id] != UINT64_MAX)
  {
    int64_t byte_offset = (int64_t)ctx->label_positions[label.id] - (int64_t)current_pos;
    int64_t instr_offset = byte_offset / 4;

    uint32_t offset_mask = ((1U << offset_bits) - 1);
    uint32_t instr = base_instr & ~(offset_mask << offset_shift);
    instr |= (((uint32_t)instr_offset & offset_mask) << offset_shift);
    cj_add_u32(ctx, instr);
  }
  else
  {
    cj_add_u32(ctx, base_instr);

    if (ctx->num_fixups >= ctx->fixup_capacity)
    {
      ctx->fixup_capacity *= 2;
      ctx->fixups = realloc(ctx->fixups, sizeof(cj_fixup) * ctx->fixup_capacity);
    }

    ctx->fixups[ctx->num_fixups].label_id = label.id;
    ctx->fixups[ctx->num_fixups].patch_offset = current_pos;
    ctx->fixups[ctx->num_fixups].kind = CJ_FIXUP_KIND_ARM_BRANCH;
    ctx->fixups[ctx->num_fixups].info.arm.offset_bits = offset_bits;
    ctx->fixups[ctx->num_fixups].info.arm.offset_shift = offset_shift;
    ctx->num_fixups++;
  }
}

void cj_emit_x86_rel(cj_ctx *ctx, const uint8_t *opcode, size_t opcode_len, uint8_t disp_width,
                     cj_label label)
{
  if (!ctx || !opcode || opcode_len == 0 || disp_width == 0) return;

  for (size_t i = 0; i < opcode_len; i++) cj_add_u8(ctx, opcode[i]);

  uint64_t disp_pos = ctx->len;
  for (uint8_t i = 0; i < disp_width; i++) cj_add_u8(ctx, 0);

  int label_known =
      (label.id >= 0 && label.id < ctx->num_labels && ctx->label_positions[label.id] != UINT64_MAX);

  if (label_known)
  {
    int64_t rel = (int64_t)ctx->label_positions[label.id] - (int64_t)(disp_pos + disp_width);
    int64_t min = -(1LL << ((disp_width * 8) - 1));
    int64_t max = (1LL << ((disp_width * 8) - 1)) - 1;
    if (rel < min || rel > max) return;

    for (uint8_t b = 0; b < disp_width; b++)
      ctx->mem[disp_pos + b] = (uint8_t)((rel >> (8 * b)) & 0xFF);
  }
  else
  {
    if (ctx->num_fixups >= ctx->fixup_capacity)
    {
      ctx->fixup_capacity *= 2;
      ctx->fixups = realloc(ctx->fixups, sizeof(cj_fixup) * ctx->fixup_capacity);
    }
    ctx->fixups[ctx->num_fixups].label_id = label.id;
    ctx->fixups[ctx->num_fixups].patch_offset = disp_pos;
    ctx->fixups[ctx->num_fixups].kind = CJ_FIXUP_KIND_X86_RELATIVE;
    ctx->fixups[ctx->num_fixups].info.x86.width = disp_width;
    ctx->num_fixups++;
  }
}

void *cj_resolve_label(const cj_ctx *ctx, cj_fn module, cj_label label)
{
  if (!ctx || !module) return NULL;

  if (label.id < 0 || label.id >= ctx->num_labels) return NULL;

  uint64_t pos = ctx->label_positions[label.id];
  if (pos == UINT64_MAX) return NULL;

  if (!ctx->executable_base) return NULL;

  if (pos >= ctx->executable_code_size) return NULL;

  return (void *)(ctx->executable_base + pos);
}
