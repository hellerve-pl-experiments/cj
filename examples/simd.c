#include "ctx.h"
#include "op.h"
#include "register.h"
#include <stdio.h>

typedef void (*simd_add_fn)(float *, const float *, const float *, int);

int main(void)
{
#ifdef __x86_64__
  float a[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
  float b[8] = {8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
  float out[8] = {0};
  const int length = 8;

  cj_ctx *cj = create_cj_ctx();

  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rsi = {.type = CJ_REGISTER, .reg = "rsi"};
  cj_operand rdx = {.type = CJ_REGISTER, .reg = "rdx"};
  cj_operand rcx = {.type = CJ_REGISTER, .reg = "rcx"};

  cj_operand xmm0 = {.type = CJ_REGISTER, .reg = "xmm0"};
  cj_operand xmm1 = {.type = CJ_REGISTER, .reg = "xmm1"};

  cj_operand four = {.type = CJ_CONSTANT, .constant = 4};
  cj_operand sixteen = {.type = CJ_CONSTANT, .constant = 16};

  cj_operand dst_mem = {.type = CJ_MEMORY,
                        .mem = {.base = "rdi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_a_mem = {.type = CJ_MEMORY,
                          .mem = {.base = "rsi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_b_mem = {.type = CJ_MEMORY,
                          .mem = {.base = "rdx", .index = NULL, .scale = 1, .disp = 0}};

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

  for (int i = 0; i < length; ++i)
  {
    printf("out[%d] = %.1f\n", i, out[i]);
  }
#elif defined(__aarch64__)
  // ARM64 NEON version
  float a[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
  float b[8] = {8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
  float out[8] = {0};
  const int length = 8;

  cj_ctx *cj = create_cj_ctx();

  // ARM64 calling convention: x0=dst, x1=src_a, x2=src_b, x3=length
  cj_operand x0 = {.type = CJ_REGISTER, .reg = "x0"};
  cj_operand x1 = {.type = CJ_REGISTER, .reg = "x1"};
  cj_operand x2 = {.type = CJ_REGISTER, .reg = "x2"};
  cj_operand x3 = {.type = CJ_REGISTER, .reg = "x3"};
  cj_operand w3 = {.type = CJ_REGISTER, .reg = "w3"};

  // NEON registers
  // Note: Use Q registers for load/store, V registers for arithmetic
  // (q0 and v0.4s refer to the same physical register)
  cj_operand q0 = {.type = CJ_REGISTER, .reg = "q0"};
  cj_operand q1 = {.type = CJ_REGISTER, .reg = "q1"};
  cj_operand v0 = {.type = CJ_REGISTER, .reg = "v0.4s"}; // 4 single-precision floats
  cj_operand v1 = {.type = CJ_REGISTER, .reg = "v1.4s"};

  cj_operand four = {.type = CJ_CONSTANT, .constant = 4};
  cj_operand sixteen = {.type = CJ_CONSTANT, .constant = 16};

  // Memory operands
  cj_operand dst_mem = {.type = CJ_MEMORY,
                        .mem = {.base = "x0", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_a_mem = {.type = CJ_MEMORY,
                          .mem = {.base = "x1", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_b_mem = {.type = CJ_MEMORY,
                          .mem = {.base = "x2", .index = NULL, .scale = 1, .disp = 0}};

  cj_label loop = cj_create_label(cj);
  cj_label done = cj_create_label(cj);

  // if (length < 4) goto done
  cj_cmp(cj, w3, four);
  cj_blt(cj, done);

  cj_mark_label(cj, loop);

  // Load 4 floats from each array (use Q registers for load/store)
  cj_ldr(cj, q0, src_a_mem); // q0 = [a[0], a[1], a[2], a[3]]
  cj_ldr(cj, q1, src_b_mem); // q1 = [b[0], b[1], b[2], b[3]]

  // Add vectors (use V registers; destructive: v0 = v0 + v1)
  // Note: cj_add works for both integer and FP vector operations
  cj_add(cj, v0, v1);

  // Store result (use Q register for store)
  cj_str(cj, q0, dst_mem); // out = q0

  // Advance pointers by 16 bytes (4 floats * 4 bytes)
  cj_add(cj, x0, sixteen);
  cj_add(cj, x1, sixteen);
  cj_add(cj, x2, sixteen);

  // Decrement counter by 4
  cj_sub(cj, w3, four);

  // if (length >= 4) goto loop
  cj_cmp(cj, w3, four);
  cj_bge(cj, loop);

  cj_mark_label(cj, done);
  cj_ret(cj);

  simd_add_fn fn = (simd_add_fn)create_cj_fn(cj);
  fn(out, a, b, length);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  for (int i = 0; i < length; ++i)
  {
    printf("out[%d] = %.1f\n", i, out[i]);
  }
#else
  puts("SIMD example not implemented for this architecture.");
#endif

  return 0;
}
