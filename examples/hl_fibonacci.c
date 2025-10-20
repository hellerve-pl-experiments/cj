#include <stdio.h>

#include "builder.h"

typedef int (*fib_fn)(int);

static int fib_c(int n) {
  if (n <= 1) return n;
  int a = 0;
  int b = 1;
  for (int i = 2; i <= n; ++i) {
    int tmp = a + b;
    a = b;
    b = tmp;
  }
  return b;
}

int main(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_builder_frame frame;
  cj_builder_fn_prologue(cj, 0, &frame);

  cj_operand n = cj_builder_arg_int(cj, 0);
  cj_operand one = cj_make_constant(1);
  cj_operand two = cj_make_constant(2);

  cj_builder_if_block early = cj_builder_if(cj, n, one, CJ_COND_LE);
  cj_builder_return_value(cj, &frame, n);
  cj_builder_endif(cj, &early);

  cj_operand acc_a = cj_builder_scratch_reg(0);
  cj_operand acc_b = cj_builder_scratch_reg(1);
  cj_operand tmp = cj_builder_scratch_reg(2);
  cj_operand i = cj_builder_scratch_reg(3);

  cj_builder_assign(cj, acc_a, cj_builder_zero_operand());
  cj_builder_assign(cj, acc_b, one);

  cj_builder_for_loop loop = cj_builder_for_begin(cj, i, one, n, one, CJ_COND_GE);

  cj_builder_assign(cj, tmp, acc_a);
  cj_builder_add_assign(cj, tmp, acc_b);
  cj_builder_assign(cj, acc_a, acc_b);
  cj_builder_assign(cj, acc_b, tmp);

  cj_builder_for_end(cj, &loop);
  cj_builder_return_value(cj, &frame, acc_b);

  fib_fn fib_jit = (fib_fn)create_cj_fn(cj);
  if (!fib_jit) {
    puts("failed to create jit function");
    destroy_cj_ctx(cj);
    return 1;
  }

  int all_pass = 1;
  for (int idx = 0; idx <= 15; ++idx) {
    int result = fib_jit(idx);
    int expected = fib_c(idx);
    int pass = (result == expected);
    all_pass &= pass;
    printf("fib(%d) = %d (expected %d)%s\n",
           idx, result, expected, pass ? "" : "  <-- mismatch");
  }

  destroy_cj_fn(cj, (cj_fn)fib_jit);
  destroy_cj_ctx(cj);

  return all_pass ? 0 : 1;
}
