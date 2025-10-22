#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "builder.h"

typedef int (*fn1_t)(int);
typedef int (*fn2_t)(int, int);

static void test_assign_and_add(void) {
  cj_ctx *cj = create_cj_ctx();
  cj_builder_frame frame;
  cj_builder_fn_prologue(cj, 0, &frame);

  cj_operand arg0 = cj_builder_arg_int(cj, 0);
  cj_operand temp = cj_builder_scratch_reg(0);
  cj_operand five = cj_make_constant(5);

  cj_builder_assign(cj, temp, five);
  cj_builder_add_assign(cj, temp, arg0);
  cj_builder_return_value(cj, &frame, temp);

  fn1_t fn = (fn1_t)create_cj_fn(cj);
  assert(fn);
  assert(fn(7) == 12);
  assert(fn(10) == 15);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_scratch_helpers(void) {
  cj_ctx *cj = create_cj_ctx();
  cj_builder_frame frame;
  cj_builder_fn_prologue(cj, 0, &frame);

  cj_builder_scratch scratch;
  cj_builder_scratch_init(&scratch);

  cj_operand acc = cj_builder_scratch_acquire(&scratch);
  cj_operand tmp = cj_builder_scratch_acquire(&scratch);

  cj_builder_assign(cj, acc, cj_builder_arg_int(cj, 0));
  cj_builder_assign(cj, tmp, cj_make_constant(7));
  cj_builder_add_assign(cj, acc, tmp);

  cj_builder_scratch_release(&scratch); // release tmp

  cj_operand adjust = cj_builder_scratch_acquire(&scratch);
  cj_builder_assign(cj, adjust, cj_make_constant(3));
  cj_builder_sub_assign(cj, acc, adjust);

  cj_builder_scratch_release(&scratch); // release adjust

  cj_builder_return_value(cj, &frame, acc);
  cj_builder_scratch_release(&scratch); // release acc

  fn1_t fn = (fn1_t)create_cj_fn(cj);
  assert(fn);
  assert(fn(0) == 4);
  assert(fn(5) == 9);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_call_helper(void) {
  cj_ctx *cj = create_cj_ctx();
  cj_label entry = cj_create_label(cj);
  cj_label callee = cj_create_label(cj);

  // Main function
  cj_mark_label(cj, entry);
  cj_builder_frame main_frame;
  cj_builder_fn_prologue_with_link_save(cj, 0, &main_frame);
  cj_builder_scratch scratch;
  cj_builder_scratch_init(&scratch);

  cj_operand arg = cj_builder_scratch_acquire(&scratch);
  cj_builder_assign(cj, arg, cj_builder_arg_int(cj, 0));
  cj_builder_add_assign(cj, arg, cj_make_constant(2));

  cj_operand call_result = cj_builder_call_unary(cj, &scratch, callee, arg);
  cj_builder_return_value(cj, &main_frame, call_result);
  cj_builder_scratch_release(&scratch);

  // Callee function: returns x + 1
  cj_mark_label(cj, callee);
  cj_builder_frame callee_frame;
  cj_builder_fn_prologue(cj, 0, &callee_frame);
  cj_operand callee_arg = cj_builder_arg_int(cj, 0);
  cj_operand tmp = cj_builder_scratch_reg(0);
  cj_builder_assign(cj, tmp, callee_arg);
  cj_builder_add_assign(cj, tmp, cj_make_constant(1));
  cj_builder_return_value(cj, &callee_frame, tmp);

  cj_fn module = create_cj_fn(cj);
  assert(module);

  fn1_t fn = (fn1_t)cj_resolve_label(cj, module, entry);
  assert(fn);
  assert(fn(10) == 13);
  assert(fn(-4) == -1);

  destroy_cj_fn(cj, module);
  destroy_cj_ctx(cj);
}

static void test_for_loop_sum(void) {
  cj_ctx *cj = create_cj_ctx();
  cj_builder_frame frame;
  cj_builder_fn_prologue(cj, 0, &frame);

  cj_operand start = cj_builder_arg_int(cj, 0);
  cj_operand end = cj_builder_arg_int(cj, 1);

  cj_operand sum = cj_builder_scratch_reg(0);
  cj_builder_assign(cj, sum, cj_builder_zero_operand());

  cj_operand i = cj_builder_scratch_reg(1);
  cj_builder_for_loop loop =
      cj_builder_for_begin(cj, i, start, end, cj_make_constant(1), CJ_COND_G);
  cj_builder_add_assign(cj, sum, i);
  cj_builder_for_end(cj, &loop);

  cj_builder_return_value(cj, &frame, sum);

  fn2_t fn = (fn2_t)create_cj_fn(cj);
  assert(fn);

  assert(fn(1, 5) == 1 + 2 + 3 + 4 + 5);
  assert(fn(3, 3) == 3);
  assert(fn(2, 1) == 0); // loop should not run when start > end

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_if_else(void) {
  cj_ctx *cj = create_cj_ctx();
  cj_builder_frame frame;
  cj_builder_fn_prologue(cj, 0, &frame);

  cj_operand arg0 = cj_builder_arg_int(cj, 0);
  cj_operand result = cj_builder_scratch_reg(0);
  cj_operand zero = cj_builder_zero_operand();
  cj_operand three = cj_make_constant(3);

  cj_builder_assign(cj, result, zero);

  cj_builder_if_block block = cj_builder_if(cj, arg0, zero, CJ_COND_G);
  cj_builder_assign(cj, result, three);
  cj_builder_else(cj, &block);
  cj_builder_sub_assign(cj, result, cj_make_constant(1));
  cj_builder_endif(cj, &block);

  cj_builder_return_value(cj, &frame, result);

  fn1_t fn = (fn1_t)create_cj_fn(cj);
  assert(fn);

  assert(fn(5) == 3);
  assert(fn(-2) == -1);
  assert(fn(0) == -1);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

int main(void) {
  test_assign_and_add();
  test_scratch_helpers();
  test_call_helper();
  test_for_loop_sum();
  test_if_else();
  puts("builder harness OK");
  return 0;
}
