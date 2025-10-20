#pragma once

#include <stddef.h>

#include "ctx.h"
#include "op.h"

typedef struct {
  size_t stack_size;
} cj_builder_frame;

typedef struct {
  cj_label entry;
  cj_label exit;
} cj_builder_block;

typedef struct {
  cj_label else_label;
  cj_label end_label;
  int has_else;
} cj_builder_if_block;

typedef struct {
  cj_builder_block block;
  cj_operand counter;
  cj_operand limit;
  cj_operand step;
  cj_condition exit_cond;
} cj_builder_for_loop;

void cj_builder_fn_prologue(cj_ctx* ctx, size_t requested_stack_bytes, cj_builder_frame* frame);
void cj_builder_fn_epilogue(cj_ctx* ctx, const cj_builder_frame* frame);
void cj_builder_return(cj_ctx* ctx, const cj_builder_frame* frame);

cj_builder_block cj_builder_loop_begin(cj_ctx* ctx);
void cj_builder_loop_condition(cj_ctx* ctx, cj_builder_block block, cj_operand lhs, cj_operand rhs, cj_condition exit_cond);
void cj_builder_loop_continue(cj_ctx* ctx, cj_builder_block block);
void cj_builder_loop_break(cj_ctx* ctx, cj_builder_block block);
void cj_builder_loop_end(cj_ctx* ctx, cj_builder_block block);

cj_builder_if_block cj_builder_if(cj_ctx* ctx, cj_operand lhs, cj_operand rhs, cj_condition cond);
void cj_builder_else(cj_ctx* ctx, cj_builder_if_block* block);
void cj_builder_endif(cj_ctx* ctx, cj_builder_if_block* block);

cj_builder_for_loop cj_builder_for_begin(cj_ctx* ctx, cj_operand counter, cj_operand start, cj_operand limit, cj_operand step, cj_condition exit_cond);
void cj_builder_for_continue(cj_ctx* ctx, cj_builder_for_loop* loop);
void cj_builder_for_break(cj_ctx* ctx, cj_builder_for_loop* loop);
void cj_builder_for_end(cj_ctx* ctx, cj_builder_for_loop* loop);

cj_operand cj_builder_assign(cj_ctx* ctx, cj_operand dst, cj_operand src);
cj_operand cj_builder_add_assign(cj_ctx* ctx, cj_operand dst, cj_operand value);
cj_operand cj_builder_sub_assign(cj_ctx* ctx, cj_operand dst, cj_operand value);

cj_operand cj_builder_arg_int(cj_ctx* ctx, unsigned index);
cj_operand cj_builder_return_reg(void);
void cj_builder_return_value(cj_ctx* ctx, const cj_builder_frame* frame, cj_operand value);
cj_operand cj_builder_zero_operand(void);
void cj_builder_clear(cj_ctx* ctx, cj_operand dst);
cj_operand cj_builder_scratch_reg(unsigned index);
