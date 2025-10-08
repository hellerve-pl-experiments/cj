#include <stdio.h>
#include "ctx.h"
#include "op.h"
#include "register.h"

typedef void (*simd_add_fn)(float*, const float*, const float*, int);

int main(void) {
#ifdef __x86_64__
  float a[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
  float b[8] = {8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
  float out[8] = {0};
  const int length = 8;

  cj_ctx* cj = create_cj_ctx();

  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rsi = {.type = CJ_REGISTER, .reg = "rsi"};
  cj_operand rdx = {.type = CJ_REGISTER, .reg = "rdx"};
  cj_operand rcx = {.type = CJ_REGISTER, .reg = "rcx"};

  cj_operand xmm0 = {.type = CJ_REGISTER, .reg = "xmm0"};
  cj_operand xmm1 = {.type = CJ_REGISTER, .reg = "xmm1"};

  cj_operand four = {.type = CJ_CONSTANT, .constant = 4};
  cj_operand sixteen = {.type = CJ_CONSTANT, .constant = 16};

  cj_operand dst_mem = {.type = CJ_MEMORY, .mem = {.base = "rdi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_a_mem = {.type = CJ_MEMORY, .mem = {.base = "rsi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_b_mem = {.type = CJ_MEMORY, .mem = {.base = "rdx", .index = NULL, .scale = 1, .disp = 0}};

  cj_label loop = cj_create_label(cj);
  cj_label done = cj_create_label(cj);

  cj_cmp(cj, rcx, four);
  cj_jl(cj, done);

  cj_mark_label(cj, loop);

  cj_movups(cj, xmm0, src_a_mem);
  cj_movups(cj, xmm1, src_b_mem);
  cj_addps(cj, xmm0, xmm1);
  cj_movups(cj, dst_mem, xmm0);

  cj_add(cj, rdi, sixteen);
  cj_add(cj, rsi, sixteen);
  cj_add(cj, rdx, sixteen);
  cj_sub(cj, rcx, four);

  cj_cmp(cj, rcx, four);
  cj_jge(cj, loop);

  cj_mark_label(cj, done);
  cj_ret(cj);

  simd_add_fn fn = (simd_add_fn)create_cj_fn(cj);
  fn(out, a, b, length);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  for (int i = 0; i < length; ++i) {
    printf("out[%d] = %.1f\n", i, out[i]);
  }
#else
  puts("SIMD example is only implemented for x86-64 backends.");
#endif

  return 0;
}
