#pragma once

#include <stddef.h>

#include "ctx.h"
#include "op.h"

typedef struct
{
  size_t stack_size;
} cj_builder_frame;

typedef struct
{
  cj_label entry;
  cj_label exit;
} cj_builder_block;

typedef struct
{
  cj_label else_label;
  cj_label end_label;
  int has_else;
} cj_builder_if_block;

typedef struct
{
  cj_builder_block block;
  cj_operand counter;
  cj_operand limit;
  cj_operand step;
  cj_condition exit_cond;
} cj_builder_for_loop;

typedef struct
{
  unsigned depth;
} cj_builder_scratch;

static inline void cj_builder_fn_prologue(cj_ctx *ctx, size_t requested_stack_bytes,
                                          cj_builder_frame *frame);
static inline void cj_builder_fn_epilogue(cj_ctx *ctx, const cj_builder_frame *frame);
static inline void cj_builder_return(cj_ctx *ctx, const cj_builder_frame *frame);

static inline cj_builder_block cj_builder_loop_begin(cj_ctx *ctx);
static inline void cj_builder_loop_condition(cj_ctx *ctx, cj_builder_block block, cj_operand lhs,
                                             cj_operand rhs, cj_condition exit_cond);
static inline void cj_builder_loop_continue(cj_ctx *ctx, cj_builder_block block);
static inline void cj_builder_loop_break(cj_ctx *ctx, cj_builder_block block);
static inline void cj_builder_loop_end(cj_ctx *ctx, cj_builder_block block);

static inline cj_builder_if_block cj_builder_if(cj_ctx *ctx, cj_operand lhs, cj_operand rhs,
                                                cj_condition cond);
static inline void cj_builder_else(cj_ctx *ctx, cj_builder_if_block *block);
static inline void cj_builder_endif(cj_ctx *ctx, cj_builder_if_block *block);

static inline cj_builder_for_loop cj_builder_for_begin(cj_ctx *ctx, cj_operand counter,
                                                       cj_operand start, cj_operand limit,
                                                       cj_operand step, cj_condition exit_cond);
static inline void cj_builder_for_continue(cj_ctx *ctx, cj_builder_for_loop *loop);
static inline void cj_builder_for_break(cj_ctx *ctx, cj_builder_for_loop *loop);
static inline void cj_builder_for_end(cj_ctx *ctx, cj_builder_for_loop *loop);

static inline cj_operand cj_builder_assign(cj_ctx *ctx, cj_operand dst, cj_operand src);
static inline cj_operand cj_builder_add_assign(cj_ctx *ctx, cj_operand dst, cj_operand value);
static inline cj_operand cj_builder_sub_assign(cj_ctx *ctx, cj_operand dst, cj_operand value);

static inline cj_operand cj_builder_arg_int(cj_ctx *ctx, unsigned index);
static inline cj_operand cj_builder_return_reg(void);
static inline void cj_builder_return_value(cj_ctx *ctx, const cj_builder_frame *frame,
                                           cj_operand value);
static inline cj_operand cj_builder_zero_operand(void);
static inline void cj_builder_clear(cj_ctx *ctx, cj_operand dst);
static inline cj_operand cj_builder_scratch_reg(unsigned index);
static inline unsigned cj_builder_scratch_capacity(void);
static inline void cj_builder_scratch_init(cj_builder_scratch *scratch);
static inline cj_operand cj_builder_scratch_acquire(cj_builder_scratch *scratch);
static inline void cj_builder_scratch_release(cj_builder_scratch *scratch);
static inline unsigned cj_builder_arg_int_capacity(void);
static inline void cj_builder_call_label(cj_ctx *ctx, cj_label target);
static inline cj_operand
cj_builder_call(cj_ctx *ctx, cj_builder_scratch *scratch, cj_label target,
                const cj_operand *args, size_t arg_count);
static inline cj_operand cj_builder_call_unary(cj_ctx *ctx, cj_builder_scratch *scratch,
                                               cj_label target, cj_operand arg0);

#include <assert.h>
#include <stdint.h>
#include <string.h>

static inline size_t align_stack_size(size_t size)
{
  const size_t alignment = 16;
  if (size == 0)
    return 0;
  size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}

static inline void cj_builder_fn_prologue(cj_ctx *ctx, size_t requested_stack_bytes,
                                          cj_builder_frame *frame)
{
  if (!ctx)
    return;

  size_t aligned = align_stack_size(requested_stack_bytes);
  if (frame)
    frame->stack_size = aligned;

#if defined(__x86_64__) || defined(_M_X64)
  cj_operand rbp = cj_make_register("rbp");
  cj_operand rsp = cj_make_register("rsp");

  cj_push(ctx, rbp);
  cj_mov(ctx, rbp, rsp);

  if (aligned)
  {
    cj_operand amount = cj_make_constant((uint64_t)aligned);
    cj_sub(ctx, rsp, amount);
  }
#elif defined(__aarch64__) || defined(_M_ARM64)
  cj_operand sp = cj_make_register("sp");
  if (aligned)
  {
    cj_operand amount = cj_make_constant((uint64_t)aligned);
    cj_sub(ctx, sp, amount);
  }
#endif
}

static inline void cj_builder_fn_epilogue(cj_ctx *ctx, const cj_builder_frame *frame)
{
  if (!ctx)
    return;
  size_t aligned = frame ? frame->stack_size : 0;

#if defined(__x86_64__) || defined(_M_X64)
  cj_operand rbp = cj_make_register("rbp");
  cj_operand rsp = cj_make_register("rsp");

  if (aligned)
  {
    cj_operand amount = cj_make_constant((uint64_t)aligned);
    cj_add(ctx, rsp, amount);
  }

  cj_pop(ctx, rbp);
#elif defined(__aarch64__) || defined(_M_ARM64)
  cj_operand sp = cj_make_register("sp");

  if (aligned)
  {
    cj_operand amount = cj_make_constant((uint64_t)aligned);
    cj_add(ctx, sp, amount);
  }
#endif
}

static inline void cj_builder_return(cj_ctx *ctx, const cj_builder_frame *frame)
{
  if (!ctx)
    return;
  cj_builder_fn_epilogue(ctx, frame);
  cj_ret(ctx);
}

static inline cj_condition invert_condition(cj_condition cond)
{
  switch (cond)
  {
  case CJ_COND_O:
    return CJ_COND_NO;
  case CJ_COND_NO:
    return CJ_COND_O;
  case CJ_COND_B:
    return CJ_COND_NB;
  case CJ_COND_NB:
    return CJ_COND_B;
  case CJ_COND_Z:
    return CJ_COND_NZ;
  case CJ_COND_NZ:
    return CJ_COND_Z;
  case CJ_COND_BE:
    return CJ_COND_A;
  case CJ_COND_A:
    return CJ_COND_BE;
  case CJ_COND_S:
    return CJ_COND_NS;
  case CJ_COND_NS:
    return CJ_COND_S;
  case CJ_COND_P:
    return CJ_COND_NP;
  case CJ_COND_NP:
    return CJ_COND_P;
  case CJ_COND_L:
    return CJ_COND_GE;
  case CJ_COND_GE:
    return CJ_COND_L;
  case CJ_COND_LE:
    return CJ_COND_G;
  case CJ_COND_G:
    return CJ_COND_LE;
  default:
    return CJ_COND_NE;
  }
}

static inline void branch_on_condition(cj_ctx *ctx, cj_condition cond, cj_label target)
{
#if defined(__x86_64__) || defined(_M_X64)
  switch (cond)
  {
  case CJ_COND_O:
    cj_jo(ctx, target);
    break;
  case CJ_COND_NO:
    cj_jno(ctx, target);
    break;
  case CJ_COND_B:
    cj_jb(ctx, target);
    break;
  case CJ_COND_NB:
    cj_jnb(ctx, target);
    break;
  case CJ_COND_Z:
    cj_jz(ctx, target);
    break;
  case CJ_COND_NZ:
    cj_jnz(ctx, target);
    break;
  case CJ_COND_BE:
    cj_jbe(ctx, target);
    break;
  case CJ_COND_A:
    cj_ja(ctx, target);
    break;
  case CJ_COND_S:
    cj_js(ctx, target);
    break;
  case CJ_COND_NS:
    cj_jns(ctx, target);
    break;
  case CJ_COND_P:
    cj_jp(ctx, target);
    break;
  case CJ_COND_NP:
    cj_jnp(ctx, target);
    break;
  case CJ_COND_L:
    cj_jl(ctx, target);
    break;
  case CJ_COND_GE:
    cj_jge(ctx, target);
    break;
  case CJ_COND_LE:
    cj_jle(ctx, target);
    break;
  case CJ_COND_G:
    cj_jg(ctx, target);
    break;
  default:
    assert(0 && "unsupported condition");
  }
#elif defined(__aarch64__) || defined(_M_ARM64)
  switch (cond)
  {
  case CJ_COND_O:
    cj_bvs(ctx, target);
    break;
  case CJ_COND_NO:
    cj_bvc(ctx, target);
    break;
  case CJ_COND_B:
    cj_bcc(ctx, target);
    break;
  case CJ_COND_NB:
    cj_bcs(ctx, target);
    break;
  case CJ_COND_Z:
    cj_beq(ctx, target);
    break;
  case CJ_COND_NZ:
    cj_bne(ctx, target);
    break;
  case CJ_COND_BE:
    cj_bls(ctx, target);
    break;
  case CJ_COND_A:
    cj_bhi(ctx, target);
    break;
  case CJ_COND_S:
    cj_bmi(ctx, target);
    break;
  case CJ_COND_NS:
    cj_bpl(ctx, target);
    break;
  case CJ_COND_L:
    cj_blt(ctx, target);
    break;
  case CJ_COND_GE:
    cj_bge(ctx, target);
    break;
  case CJ_COND_LE:
    cj_ble(ctx, target);
    break;
  case CJ_COND_G:
    cj_bgt(ctx, target);
    break;
  default:
    assert(0 && "unsupported condition on arm64");
  }
#endif
}

static inline void branch_unconditional(cj_ctx *ctx, cj_label target)
{
#if defined(__x86_64__) || defined(_M_X64)
  cj_jmp(ctx, target);
#elif defined(__aarch64__) || defined(_M_ARM64)
  cj_b(ctx, target);
#endif
}

static inline cj_builder_block cj_builder_loop_begin(cj_ctx *ctx)
{
  cj_builder_block block = {
      .entry = cj_create_label(ctx),
      .exit = cj_create_label(ctx),
  };
  cj_mark_label(ctx, block.entry);
  return block;
}

static inline void cj_builder_loop_condition(cj_ctx *ctx, cj_builder_block block, cj_operand lhs,
                                             cj_operand rhs, cj_condition exit_cond)
{
  if (!ctx)
    return;
  cj_cmp(ctx, lhs, rhs);
  branch_on_condition(ctx, exit_cond, block.exit);
}

static inline void cj_builder_loop_continue(cj_ctx *ctx, cj_builder_block block)
{
  if (!ctx)
    return;
  branch_unconditional(ctx, block.entry);
}

static inline void cj_builder_loop_break(cj_ctx *ctx, cj_builder_block block)
{
  if (!ctx)
    return;
  branch_unconditional(ctx, block.exit);
}

static inline void cj_builder_loop_end(cj_ctx *ctx, cj_builder_block block)
{
  if (!ctx)
    return;
  branch_unconditional(ctx, block.entry);
  cj_mark_label(ctx, block.exit);
}

cj_builder_if_block cj_builder_if(cj_ctx *ctx, cj_operand lhs, cj_operand rhs, cj_condition cond)
{
  cj_builder_if_block block = {
      .else_label = cj_create_label(ctx),
      .end_label = cj_create_label(ctx),
      .has_else = 0,
  };
  cj_cmp(ctx, lhs, rhs);
  branch_on_condition(ctx, invert_condition(cond), block.else_label);
  return block;
}

void cj_builder_else(cj_ctx *ctx, cj_builder_if_block *block)
{
  if (!ctx || !block)
    return;
  branch_unconditional(ctx, block->end_label);
  cj_mark_label(ctx, block->else_label);
  block->has_else = 1;
}

void cj_builder_endif(cj_ctx *ctx, cj_builder_if_block *block)
{
  if (!ctx || !block)
    return;
  if (!block->has_else)
  {
    cj_mark_label(ctx, block->else_label);
  }
  cj_mark_label(ctx, block->end_label);
}

static inline cj_builder_for_loop cj_builder_for_begin(cj_ctx *ctx, cj_operand counter,
                                                       cj_operand start, cj_operand limit,
                                                       cj_operand step, cj_condition exit_cond)
{
  cj_builder_for_loop loop = {
      .counter = counter,
      .limit = limit,
      .step = step,
      .exit_cond = exit_cond,
  };

  if (counter.type == CJ_REGISTER)
  {
    cj_mov(ctx, counter, start);
  }

  loop.block = cj_builder_loop_begin(ctx);
  cj_builder_loop_condition(ctx, loop.block, counter, limit, exit_cond);
  return loop;
}

static inline void cj_builder_for_continue(cj_ctx *ctx, cj_builder_for_loop *loop)
{
  if (!ctx || !loop)
    return;
  cj_add(ctx, loop->counter, loop->step);
  cj_builder_loop_continue(ctx, loop->block);
}

static inline void cj_builder_for_break(cj_ctx *ctx, cj_builder_for_loop *loop)
{
  if (!ctx || !loop)
    return;
  cj_builder_loop_break(ctx, loop->block);
}

static inline void cj_builder_for_end(cj_ctx *ctx, cj_builder_for_loop *loop)
{
  if (!ctx || !loop)
    return;
  cj_add(ctx, loop->counter, loop->step);
  cj_builder_loop_end(ctx, loop->block);
}

static inline cj_operand cj_builder_assign(cj_ctx *ctx, cj_operand dst, cj_operand src)
{
#if defined(__aarch64__) || defined(_M_ARM64)
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT)
  {
    const char *reg = dst.reg;
    int is64 = (reg && reg[0] == 'x');
    uint64_t mask = is64 ? UINT64_MAX : 0xFFFFFFFFu;
    uint64_t value = src.constant & mask;
    if (value == 0)
    {
      cj_mov(ctx, dst, cj_builder_zero_operand());
      return dst;
    }
    cj_operand chunk = cj_make_constant((value & 0xFFFFu));
    cj_movz(ctx, dst, chunk);
    for (int shift = 16; shift < (is64 ? 64 : 32); shift += 16)
    {
      uint16_t part = (uint16_t)((value >> shift) & 0xFFFFu);
      if (!part)
        continue;
      uint64_t encoded = (uint64_t)part | ((uint64_t)(shift / 16) << 16);
      cj_operand next = cj_make_constant(encoded);
      cj_movk(ctx, dst, next);
    }
    return dst;
  }
#endif
  if (dst.type == CJ_REGISTER)
  {
    cj_mov(ctx, dst, src);
    return dst;
  }
  if (dst.type == CJ_MEMORY)
  {
    cj_mov(ctx, dst, src);
    return dst;
  }
  return dst;
}

static inline cj_operand cj_builder_add_assign(cj_ctx *ctx, cj_operand dst, cj_operand value)
{
  cj_add(ctx, dst, value);
  return dst;
}

static inline cj_operand cj_builder_sub_assign(cj_ctx *ctx, cj_operand dst, cj_operand value)
{
  cj_sub(ctx, dst, value);
  return dst;
}

static inline cj_operand get_return_operand(void)
{
#if defined(__x86_64__) || defined(_M_X64)
  return cj_make_register("eax");
#elif defined(__aarch64__) || defined(_M_ARM64)
  return cj_make_register("w0");
#endif
}

static inline cj_operand cj_builder_return_reg(void)
{
  return get_return_operand();
}

static inline cj_operand cj_builder_arg_int(cj_ctx *ctx, unsigned index)
{
  (void)ctx;
#if defined(__x86_64__) || defined(_M_X64)
  static const char *regs[] = {"edi", "esi", "edx", "ecx", "r8d", "r9d"};
  const size_t count = sizeof(regs) / sizeof(regs[0]);
  assert(index < count);
  (void)count;
  return cj_make_register(regs[index]);
#elif defined(__aarch64__) || defined(_M_ARM64)
  static const char *regs[] = {"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"};
  const size_t count = sizeof(regs) / sizeof(regs[0]);
  assert(index < count);
  (void)count;
  return cj_make_register(regs[index]);
#endif
}

static inline void cj_builder_return_value(cj_ctx *ctx, const cj_builder_frame *frame,
                                           cj_operand value)
{
  if (!ctx)
    return;
  cj_operand ret = get_return_operand();
  int needs_move = 1;
  if (value.type == CJ_REGISTER && value.reg && ret.reg)
  {
    if (strcmp(value.reg, ret.reg) == 0)
    {
      needs_move = 0;
    }
  }
  if (needs_move)
  {
    cj_mov(ctx, ret, value);
  }
  cj_builder_return(ctx, frame);
}

static inline cj_operand cj_builder_zero_operand(void)
{
#if defined(__x86_64__) || defined(_M_X64)
  return cj_make_constant(0);
#elif defined(__aarch64__) || defined(_M_ARM64)
  return cj_make_register("wzr");
#endif
}

static inline void cj_builder_clear(cj_ctx *ctx, cj_operand dst)
{
  if (!ctx)
    return;
#if defined(__x86_64__) || defined(_M_X64)
  if (dst.type == CJ_REGISTER)
  {
    cj_xor(ctx, dst, dst);
    return;
  }
#endif
  cj_mov(ctx, dst, cj_builder_zero_operand());
}

static inline cj_operand cj_builder_scratch_reg(unsigned index)
{
#if defined(__x86_64__) || defined(_M_X64)
  static const char *regs[] = {"r8d", "r9d", "r10d", "r11d", "ecx", "edx"};
  const size_t count = sizeof(regs) / sizeof(regs[0]);
  assert(index < count);
  (void)count;
  return cj_make_register(regs[index]);
#elif defined(__aarch64__) || defined(_M_ARM64)
  static const char *regs[] = {"w2", "w3", "w4", "w5", "w6", "w7"};
  const size_t count = sizeof(regs) / sizeof(regs[0]);
  assert(index < count);
  (void)count;
  return cj_make_register(regs[index]);
#endif
}

static inline unsigned cj_builder_scratch_capacity(void)
{
#if defined(__x86_64__) || defined(_M_X64)
  return 6;
#elif defined(__aarch64__) || defined(_M_ARM64)
  return 6;
#endif
}

static inline unsigned cj_builder_arg_int_capacity(void)
{
#if defined(__x86_64__) || defined(_M_X64)
  return 6;
#elif defined(__aarch64__) || defined(_M_ARM64)
  return 8;
#endif
}

static inline void cj_builder_scratch_init(cj_builder_scratch *scratch)
{
  if (!scratch)
    return;
  scratch->depth = 0;
}

static inline cj_operand cj_builder_scratch_acquire(cj_builder_scratch *scratch)
{
  assert(scratch);
  assert(scratch->depth < cj_builder_scratch_capacity());
  unsigned index = scratch->depth++;
  return cj_builder_scratch_reg(index);
}

static inline void cj_builder_scratch_release(cj_builder_scratch *scratch)
{
  assert(scratch);
  assert(scratch->depth > 0);
  scratch->depth--;
}

static inline void cj_builder_call_label(cj_ctx *ctx, cj_label target)
{
#if defined(__x86_64__) || defined(_M_X64)
  cj_call(ctx, target);
#elif defined(__aarch64__) || defined(_M_ARM64)
  cj_bl(ctx, target);
#endif
}

static inline cj_operand cj_builder_call_unary(cj_ctx *ctx, cj_builder_scratch *scratch,
                                               cj_label target, cj_operand arg0)
{
  const cj_operand args[] = {arg0};
  return cj_builder_call(ctx, scratch, target, args, 1);
}

static inline cj_operand
cj_builder_call(cj_ctx *ctx, cj_builder_scratch *scratch, cj_label target,
                const cj_operand *args, size_t arg_count)
{
  if (!ctx)
    return cj_builder_return_reg();

  unsigned capacity = cj_builder_arg_int_capacity();
  assert(arg_count <= capacity);

  for (size_t i = 0; i < arg_count; ++i)
  {
    cj_operand reg = cj_builder_arg_int(ctx, (unsigned)i);
    cj_builder_assign(ctx, reg, args[i]);
  }

  if (scratch)
    cj_builder_scratch_release(scratch);

  cj_builder_call_label(ctx, target);

  if (scratch)
  {
    cj_operand dst = cj_builder_scratch_acquire(scratch);
    cj_builder_assign(ctx, dst, cj_builder_return_reg());
    return dst;
  }

  return cj_builder_return_reg();
}
