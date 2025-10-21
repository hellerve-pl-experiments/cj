#include "ctx.h"
#include "op.h"
#include <stdio.h>

typedef int (*add_fn)(int);

int main(void)
{
  cj_ctx *cj = create_cj_ctx();

#ifdef __aarch64__
  cj_operand reg = {.type = CJ_REGISTER, .reg = "x0"};
#else
  cj_operand reg = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand arg = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_mov(cj, reg, arg);
#endif

  cj_operand val = {.type = CJ_CONSTANT, .constant = 32};

  cj_add(cj, reg, val);
  cj_ret(cj);

  add_fn f = (add_fn)create_cj_fn(cj);

  int res = f(10);

  destroy_cj_fn(cj, (cj_fn)f);
  destroy_cj_ctx(cj);

  return res;
}
