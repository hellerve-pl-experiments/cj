#include <assert.h>
#include <stdio.h>
#include <string.h>

#if !defined(__x86_64__) && !defined(_M_X64)
#error "This harness must be built on an x86-64 target."
#endif

#ifndef __x86_64__
#define __x86_64__ 1
#endif

#include "ctx.h"
#include "op.h"
#include "register.h"

static void test_add_constant(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand constant = {.type = CJ_CONSTANT, .constant = 32};

  cj_mov(cj, rax, rdi);
  cj_add(cj, rax, constant);
  cj_ret(cj);

  typedef int (*fn_t)(int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(10);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_branch_loop(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rcx = {.type = CJ_REGISTER, .reg = "rcx"};
  cj_operand zero = {.type = CJ_CONSTANT, .constant = 0};
  cj_operand one = {.type = CJ_CONSTANT, .constant = 1};

  cj_label loop = cj_create_label(cj);
  cj_label done = cj_create_label(cj);

  cj_mov(cj, rax, zero);
  cj_mov(cj, rcx, one);

  cj_mark_label(cj, loop);
  cj_cmp(cj, rcx, rdi);
  cj_jg(cj, done);
  cj_add(cj, rax, rcx);
  cj_add(cj, rcx, one);
  cj_jmp(cj, loop);

  cj_mark_label(cj, done);
  cj_ret(cj);

  typedef int (*fn_t)(int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(5);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 15);
}

static void test_simd_add(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rsi = {.type = CJ_REGISTER, .reg = "rsi"};
  cj_operand rdx = {.type = CJ_REGISTER, .reg = "rdx"};
  cj_operand rcx = {.type = CJ_REGISTER, .reg = "rcx"};
  cj_operand xmm0 = {.type = CJ_REGISTER, .reg = "xmm0"};
  cj_operand xmm1 = {.type = CJ_REGISTER, .reg = "xmm1"};
  cj_operand sixteen = {.type = CJ_CONSTANT, .constant = 16};
  cj_operand four = {.type = CJ_CONSTANT, .constant = 4};

  cj_operand dst = {.type = CJ_MEMORY, .mem = {.base = "rdi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_a = {.type = CJ_MEMORY, .mem = {.base = "rsi", .index = NULL, .scale = 1, .disp = 0}};
  cj_operand src_b = {.type = CJ_MEMORY, .mem = {.base = "rdx", .index = NULL, .scale = 1, .disp = 0}};

  cj_label loop = cj_create_label(cj);
  cj_label done = cj_create_label(cj);

  cj_cmp(cj, rcx, four);
  cj_jl(cj, done);

  cj_mark_label(cj, loop);
  cj_movups(cj, xmm0, src_a);
  cj_movups(cj, xmm1, src_b);
  cj_addps(cj, xmm0, xmm1);
  cj_movups(cj, dst, xmm0);

  cj_add(cj, rdi, sixteen);
  cj_add(cj, rsi, sixteen);
  cj_add(cj, rdx, sixteen);
  cj_sub(cj, rcx, four);

  cj_cmp(cj, rcx, four);
  cj_jge(cj, loop);

  cj_mark_label(cj, done);
  cj_ret(cj);

  typedef void (*fn_t)(float*, const float*, const float*, int);
  fn_t fn = (fn_t)create_cj_fn(cj);

  float out[8] = {0};
  float a[8] = {1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f, 8.f};
  float b[8] = {8.f, 7.f, 6.f, 5.f, 4.f, 3.f, 2.f, 1.f};

  fn(out, a, b, 8);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  for (int i = 0; i < 8; ++i) {
    assert(out[i] == 9.f);
  }
}

static void test_string_movsb(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rsi = {.type = CJ_REGISTER, .reg = "rsi"};
  cj_operand rdx = {.type = CJ_REGISTER, .reg = "rdx"};
  cj_operand rcx = {.type = CJ_REGISTER, .reg = "rcx"};

  cj_mov(cj, rcx, rdx);
  cj_cld(cj);
  cj_add_u8(cj, 0xf3);
  cj_movsb(cj);
  cj_ret(cj);

  typedef void (*fn_t)(char*, const char*, size_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  const char src[] = "JIT string test";
  char dst[sizeof(src)] = {0};
  fn(dst, src, sizeof(src));

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(memcmp(dst, src, sizeof(src)) == 0);
}

static void test_negative_immediate(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand neg_one = {.type = CJ_CONSTANT, .constant = -1};

  cj_mov(cj, rax, rdi);
  cj_add(cj, rax, neg_one);
  cj_ret(cj);

  typedef int (*fn_t)(int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(42);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 41);
}

static void test_negative_immediate_sub(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand neg_five = {.type = CJ_CONSTANT, .constant = -5};

  cj_mov(cj, rax, rdi);
  cj_sub(cj, rax, neg_five);
  cj_ret(cj);

  typedef int (*fn_t)(int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(10);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 15);
}

static void test_immediate_boundaries(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand min_imm8 = {.type = CJ_CONSTANT, .constant = -128};
  cj_operand max_imm8 = {.type = CJ_CONSTANT, .constant = 127};

  cj_mov(cj, rax, rdi);
  cj_add(cj, rax, min_imm8);
  cj_add(cj, rax, max_imm8);
  cj_ret(cj);

  typedef int (*fn_t)(int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(100);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 99);
}

static void test_memory_addressing(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand mem = {.type = CJ_MEMORY, .mem = {.base = "rdi", .index = NULL, .scale = 1, .disp = 4}};

  cj_mov(cj, rax, mem);
  cj_ret(cj);

  typedef int (*fn_t)(int*);
  fn_t fn = (fn_t)create_cj_fn(cj);

  int values[3] = {10, 20, 30};
  int res = fn(values);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 20);
}

static void test_extended_registers(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand rax = {.type = CJ_REGISTER, .reg = "rax"};
  cj_operand rdi = {.type = CJ_REGISTER, .reg = "rdi"};
  cj_operand rsi = {.type = CJ_REGISTER, .reg = "rsi"};
  cj_operand r8 = {.type = CJ_REGISTER, .reg = "r8"};

  cj_mov(cj, rax, rdi);
  cj_mov(cj, r8, rsi);
  cj_add(cj, rax, r8);
  cj_ret(cj);

  typedef int (*fn_t)(int, int);
  fn_t fn = (fn_t)create_cj_fn(cj);
  int res = fn(100, 200);
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 300);
}

int main(void) {
  test_add_constant();
  test_branch_loop();
  test_simd_add();
  test_string_movsb();
  test_negative_immediate();
  test_negative_immediate_sub();
  test_immediate_boundaries();
  test_memory_addressing();
  test_extended_registers();
  return 0;
}
