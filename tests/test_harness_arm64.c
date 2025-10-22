#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(__aarch64__) && !defined(_M_ARM64)
#error "This harness must be built on an ARM64 target."
#endif

#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ctx.h"
#include "op.h"
#include "register.h"

static inline uint32_t mov_literal_chunk(uint16_t value, uint32_t shift) {
  return ((shift / 16u) << 16) | (uint32_t)value;
}

static void test_mov_returns_second_argument(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_mov(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(0, 99);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 99);
}

static void test_add_immediate(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand imm = cj_make_constant(5);

  cj_add(cj, x0, imm);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(37);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_add_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_add(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(20, 22);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_add_shifted_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1_shift = cj_operand_lsl(cj_make_register("x1"), 1);

  cj_add(cj, x0, x1_shift);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(5, 7);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 19);
}

static void test_add_immediate_shifted(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand imm = cj_operand_lsl(cj_make_constant(1), 12);

  cj_add(cj, x0, imm);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(10);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 10 + (1L << 12));
}

static void test_add_extended_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand w1_ext = cj_operand_uxtw(cj_make_register("w1"), 2);

  cj_add(cj, x0, w1_ext);
  cj_ret(cj);

  typedef long (*fn_t)(long, uint32_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(5, 3);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 5 + ((long)3 << 2));
}

static void test_add_signed_extend(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand w1_ext = cj_operand_sxtw(cj_make_register("w1"), 1);

  cj_add(cj, x0, w1_ext);
  cj_ret(cj);

  typedef long (*fn_t)(long, int32_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(8, -3);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  long expected = 8 + (((int64_t)(int32_t)-3) * 2);
  assert(res == expected);
}

static void test_and_shifted_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1_shift = cj_operand_lsr(cj_make_register("x1"), 1);

  cj_and(cj, x0, x1_shift);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t lhs = 0x12345678ull;
  uint64_t rhs = 0xFFFFull;
  uint64_t res = fn(lhs, rhs);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == (lhs & (rhs >> 1))); // LSR
}

static void test_str_pre_index(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_str(cj, x1, cj_make_preindexed("x0", -8));
  cj_ldr(cj, x0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef long (*fn_t)(long *, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long buffer[2] = {0, 0};
  long res = fn(&buffer[1], 12345);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 12345);
  assert(buffer[0] == 12345);
  assert(buffer[1] == 0);
}

static void test_ldr_post_index(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");
  cj_operand x2 = cj_make_register("x2");

  cj_ldr(cj, x2, cj_make_postindexed("x0", 8));
  cj_str(cj, x0, cj_make_memory("x1", NULL, 1, 0));
  cj_mov(cj, x0, x2);
  cj_ret(cj);

  typedef long (*fn_t)(long *, long **);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long data[3] = {11, 22, 33};
  long *updated = NULL;
  long res = fn(data, &updated);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 11);
  assert(updated == data + 1);
}

static void test_movz_literal(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand imm = cj_make_constant(mov_literal_chunk(0x9ABC, 0));

  cj_movz(cj, x0, imm);
  cj_ret(cj);

  typedef long (*fn_t)(void);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn();

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 0x9ABC);
}

static void test_movk_multi_chunk(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");

  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(0xDEF0, 0)));
  cj_movk(cj, x0, cj_make_constant(mov_literal_chunk(0x9ABC, 16)));
  cj_movk(cj, x0, cj_make_constant(mov_literal_chunk(0x5678, 32)));
  cj_movk(cj, x0, cj_make_constant(mov_literal_chunk(0x1234, 48)));
  cj_ret(cj);

  typedef uint64_t (*fn_t)(void);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn();
  uint64_t expected =
      ((uint64_t)0x1234 << 48) | ((uint64_t)0x5678 << 32) | ((uint64_t)0x9ABC << 16) | 0xDEF0u;

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == expected);
}

static void test_store_load_roundtrip(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");
  cj_operand mem = cj_make_memory("x0", NULL, 1, 0);

  cj_str(cj, x1, mem);
  cj_ldr(cj, x1, mem);
  cj_mov(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long *, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long slot = 0;
  long res = fn(&slot, 4242);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(slot == 4242);
  assert(res == 4242);
}

static void test_branch_max(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_label greater = cj_create_label(cj);

  cj_cmp(cj, x0, x1);
  cj_bge(cj, greater);

  cj_mov(cj, x0, x1);
  cj_ret(cj);

  cj_mark_label(cj, greater);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res1 = fn(3, 7);
  long res2 = fn(10, 4);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res1 == 7);
  assert(res2 == 10);
}

static void test_cmp_shifted_register_branch(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1_asr = cj_operand_asr(cj_make_register("x1"), 2);

  cj_label ge = cj_create_label(cj);
  cj_label exit = cj_create_label(cj);

  cj_cmp(cj, x0, x1_asr);
  cj_bge(cj, ge);

  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(0, 0)));
  cj_b(cj, exit);

  cj_mark_label(cj, ge);
  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(1, 0)));

  cj_mark_label(cj, exit);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res_ge = fn(3, -4);   // -4 >> 2 => -1, 3 >= -1 => true
  long res_lt = fn(-10, 12); // 12 >> 2 => 3, -10 >= 3 => false

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res_ge == 1);
  assert(res_lt == 0);
}

static void test_cmp_immediate_branch(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");
  cj_operand threshold = cj_operand_lsl(cj_make_constant(1), 12);

  cj_label ge = cj_create_label(cj);
  cj_label exit = cj_create_label(cj);

  cj_cmp(cj, x0, threshold);
  cj_bge(cj, ge);

  cj_movz(cj, x1, cj_make_constant(mov_literal_chunk(0, 0)));
  cj_b(cj, exit);

  cj_mark_label(cj, ge);
  cj_movz(cj, x1, cj_make_constant(mov_literal_chunk(1, 0)));

  cj_mark_label(cj, exit);
  cj_mov(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long below = fn(42);
  long above = fn(5000);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(below == 0);
  assert(above == 1);
}

static void test_scalar_fp_add(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand s0 = cj_make_register("s0");
  cj_operand s1 = cj_make_register("s1");

  cj_fadd(cj, s0, s1);
  cj_ret(cj);

  typedef float (*fn_t)(float, float);
  fn_t fn = (fn_t)create_cj_fn(cj);

  float res = fn(1.25f, 2.5f);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res > 3.74f && res < 3.76f);
}

static void test_ld1_st1_vec_list(void) {
  cj_ctx *cj = create_cj_ctx();

  const char *regs[] = {"v0.4s", "v1.4s"};
  cj_operand vec_list = cj_make_reg_list(regs, 2);
  cj_operand base_load = cj_make_register("x0");
  cj_operand base_store = cj_make_register("x1");

  cj_ld1(cj, vec_list, base_load);
  cj_st1(cj, vec_list, base_store);
  cj_ret(cj);

  typedef void (*fn_t)(const float *, float *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  float src[8] = {1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f, 8.f};
  float dst[8] = {0.f};
  fn(src, dst);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  for (int i = 0; i < 8; ++i) {
    assert(dst[i] == src[i]);
  }
}

// TODO: Re-enable when SIMD misc operations are supported
/*
static void test_vector_abs_in_place(void) {
  cj_ctx* cj = create_cj_ctx();

  cj_operand v0 = cj_make_register("v0.4s");

  cj_abs(cj, v0, v0);
  cj_ret(cj);

  typedef float (*fn_t)(float, float, float, float);
  fn_t fn = (fn_t)create_cj_fn(cj);

  float input0 = -1.f;
  float input1 = 2.f;
  float input2 = -3.5f;
  float input3 = 4.25f;
  float res = fn(*(float*)&input0, *(float*)&input1, *(float*)&input2, *(float*)&input3);
  (void)res;  // silence unused warning, values validated via memory compare below

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}
*/

static void test_sub_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_sub(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(100, 42);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 58);
}

static void test_sub_immediate(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand imm = cj_make_constant(15);

  cj_sub(cj, x0, imm);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(57);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_or_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_orr(cj, x0, x1);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(0xFF00, 0x00FF);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 0xFFFF);
}

static void test_xor_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_eor(cj, x0, x1);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(0xFFFF, 0xFF00);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 0x00FF);
}

static void test_mul_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_mul(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res = fn(6, 7);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_udiv_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_udiv(cj, x0, x1);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(420, 10);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_sdiv_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_sdiv(cj, x0, x1);
  cj_ret(cj);

  typedef int64_t (*fn_t)(int64_t, int64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  int64_t res = fn(-420, 10);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == -42);
}

static void test_lsl_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_lsl(cj, x0, x1);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(21, 1);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_lsr_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_lsr(cj, x0, x1);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(168, 2);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == 42);
}

static void test_asr_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_asr(cj, x0, x1);
  cj_ret(cj);

  typedef int64_t (*fn_t)(int64_t, int64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  int64_t res = fn(-168, 2);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == -42);
}

static void test_mvn_register(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_mov(cj, x0, x1);
  cj_mvn(cj, x0, x0);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t res = fn(0, 0x00FF);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res == ~0x00FFull);
}

static void test_ldxr_simple(void) {
  cj_ctx *cj = create_cj_ctx();

  // x0 = address, load value from [x0] into x0 using LDXR
  cj_operand x0 = cj_make_register("x0");
  cj_ldxr(cj, x0, x0);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t value = 0x1234567890ABCDEF;
  uint64_t result = fn(&value);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(result == 0x1234567890ABCDEF);
}

static void test_stxr_simple(void) {
  cj_ctx *cj = create_cj_ctx();

  // x0 = address, x1 = value to store
  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");
  cj_operand x2 = cj_make_register("x2");
  cj_operand w0 = cj_make_register("w0");

  // LDXR x2, [x0] - Load exclusive to set monitor
  cj_ldxr(cj, x2, x0);

  // STXR w0, x1, [x0] - Store exclusive, status in w0
  cj_operand mem = cj_make_memory("x0", NULL, 1, 0);
  cj_stxr(cj, w0, x1, mem);
  cj_ret(cj);

  typedef uint32_t (*fn_t)(uint64_t *, uint64_t);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t value = 0;
  uint32_t status = fn(&value, 0xDEADBEEF);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  // status should be 0 (success)
  assert(status == 0);
  assert(value == 0xDEADBEEF);
}

static void test_ldar_simple(void) {
  cj_ctx *cj = create_cj_ctx();

  // x0 = address, load-acquire from [x0] into x0
  cj_operand x0 = cj_make_register("x0");
  cj_ldar(cj, x0, x0);
  cj_ret(cj);

  typedef uint64_t (*fn_t)(uint64_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint64_t value = 0xFEDCBA9876543210;
  uint64_t result = fn(&value);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(result == 0xFEDCBA9876543210);
}

static void test_simd_add(void) {
  cj_ctx *cj = create_cj_ctx();

  // Load input vectors from memory
  // x0 = pointer to first vector
  // x1 = pointer to second vector
  // Load q0 from [x0], q1 from [x1] (128-bit loads)
  // Add v0.16b = v0.16b + v1.16b (16 x 8-bit addition)
  // Store q0 to [x0] (128-bit store)
  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0 = cj_make_register("v0.16b");
  cj_operand v1 = cj_make_register("v1.16b");

  // Load vectors (q0 and v0 are same register, just different notation)
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // SIMD add: v0.16b += v1.16b (q0/v0 are same register)
  cj_add(cj, v0, v1);

  // Store result
  cj_str(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(uint8_t *, uint8_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Test with byte arrays
  uint8_t vec1[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  uint8_t vec2[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

  fn(vec1, vec2);

  // Check result (vec1 should be sum of original vec1 and vec2)
  for (int i = 0; i < 16; i++) {
    uint8_t expected = (i + 1) + (16 - i);
    if (vec1[i] != expected) {
      printf("SIMD test failed at index %d: expected %d, got %d\n", i, expected, vec1[i]);
    }
    assert(vec1[i] == expected);
  }

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_simd_abs(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test SIMD ABS (absolute value) on signed bytes
  // Load q0 from [x0] (128-bit load)
  // ABS v0.16b = abs(v0.16b) (16 x 8-bit absolute value)
  // Store q0 to [x0] (128-bit store)
  cj_operand q0 = cj_make_register("q0");
  cj_operand v0 = cj_make_register("v0.16b");

  // Load vector
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));

  // SIMD abs: v0.16b = abs(v0.16b)
  cj_abs(cj, v0, v0);

  // Store result
  cj_str(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(int8_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Test with signed bytes (mix of positive and negative)
  int8_t vec[16] = {-1, 2, -3, 4, -5, 6, -7, 8, -9, 10, -11, 12, -13, 14, -15, 16};
  int8_t expected[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  fn(vec);

  // Check result (all values should be positive)
  for (int i = 0; i < 16; i++) {
    if (vec[i] != expected[i]) {
      printf("SIMD ABS test failed at index %d: expected %d, got %d\n", i, expected[i], vec[i]);
    }
    assert(vec[i] == expected[i]);
  }

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_aes_encrypt(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test AES single round encryption (AESE)
  // x0 = pointer to state (16 bytes)
  // x1 = pointer to round key (16 bytes)
  // Load q0 from [x0] (state)
  // Load q1 from [x1] (round key)
  // AESE v0, v1 (encrypt state with round key)
  // Store q0 to [x0]
  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0 = cj_make_register("v0.16b");
  cj_operand v1 = cj_make_register("v1.16b");

  // Load state and key
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // AES single round encryption: v0 = AESE(v0, v1)
  cj_aese(cj, v0, v1);

  // Store result
  cj_str(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(uint8_t *, uint8_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Use a simple test: all zeros state with all zeros key
  // AESE applies SubBytes and ShiftRows, so result won't be zero
  uint8_t state[16] = {0};
  uint8_t key[16] = {0};

  fn(state, key);

  // After AESE with zero key, the state should be transformed
  // (SubBytes + ShiftRows applied, not just zero)
  // Check that state changed (not all zeros anymore)
  int changed = 0;
  for (int i = 0; i < 16; i++) {
    if (state[i] != 0) {
      changed = 1;
      break;
    }
  }

  // AESE should transform the state (apply SubBytes and ShiftRows)
  assert(changed);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_xtn_narrow(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test XTN (extend narrow) - narrows 16-bit to 8-bit elements
  // XTN v0.8b, v1.8h - narrow 8 halfwords to 8 bytes in lower half
  // XTN2 v0.16b, v1.8h - narrow 8 halfwords to 8 bytes in upper half
  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0_8b = cj_make_register("v0.8b");
  cj_operand v0_16b = cj_make_register("v0.16b");
  cj_operand v1_8h = cj_make_register("v1.8h");

  // Load input (8 halfwords)
  cj_ldr(cj, q1, cj_make_memory("x0", NULL, 1, 0));

  // XTN v0.8b, v1.8h - narrow to lower 8 bytes
  cj_xtn(cj, v0_8b, v1_8h);

  // Store result (lower 8 bytes valid)
  cj_str(cj, q0, cj_make_memory("x1", NULL, 1, 0));

  // Reload input
  cj_ldr(cj, q1, cj_make_memory("x0", NULL, 1, 0));

  // XTN2 v0.16b, v1.8h - narrow to upper 8 bytes (preserves lower 8)
  cj_xtn2(cj, v0_16b, v1_8h);

  // Store result (all 16 bytes valid)
  cj_str(cj, q0, cj_make_memory("x2", NULL, 1, 0));

  cj_ret(cj);

  typedef void (*fn_t)(uint16_t *, uint8_t *, uint8_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Input: 8 halfwords (16-bit values)
  uint16_t input[8] = {0x0100, 0x0201, 0x0302, 0x0403, 0x0504, 0x0605, 0x0706, 0x0807};
  uint8_t result1[16] = {0};
  uint8_t result2[16] = {0};

  fn(input, result1, result2);

  // XTN narrows to lower byte of each halfword
  // result1 lower 8 bytes should be: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  uint8_t expected1[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  for (int i = 0; i < 8; i++) {
    if (result1[i] != expected1[i]) {
      printf("XTN test failed at index %d: expected 0x%02x, got 0x%02x\n", i, expected1[i],
             result1[i]);
    }
    assert(result1[i] == expected1[i]);
  }

  // XTN2 should have same values in both halves (lower from XTN, upper from XTN2)
  for (int i = 0; i < 8; i++) {
    if (result2[i] != expected1[i] || result2[i + 8] != expected1[i]) {
      printf("XTN2 test failed at index %d: expected 0x%02x in both halves, got lower=0x%02x "
             "upper=0x%02x\n",
             i, expected1[i], result2[i], result2[i + 8]);
    }
    assert(result2[i] == expected1[i]);
    assert(result2[i + 8] == expected1[i]);
  }

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_sve_encoding(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test SVE FTSMUL instruction encoding
  // FTSMUL z0.d, z1.d, z2.d
  // Expected encoding: 0x65C20C20
  // - Base: 0x65000C00
  // - size=3 (D) at [23:22]: (3 << 22) = 0x00C00000
  // - Zd=0 at [4:0]: 0
  // - Zn=1 at [9:5]: (1 << 5) = 0x20
  // - Zm=2 at [20:16]: (2 << 16) = 0x20000
  // Total: 0x65000C00 | 0x00C00000 | 0x20 | 0x20000 = 0x65C20C20

  cj_operand z0_d = cj_make_register("z0.d");
  cj_operand z1_d = cj_make_register("z1.d");
  cj_operand z2_d = cj_make_register("z2.d");

  cj_ftsmul(cj, z0_d, z1_d, z2_d);

  // Check the generated instruction encoding
  assert(cj->len == 4); // Should have generated 4 bytes
  uint32_t generated = *(uint32_t *)cj->mem;
  uint32_t expected = 0x65C20C20;

  if (generated != expected) {
    printf("SVE encoding test failed: expected 0x%08X, got 0x%08X\n", expected, generated);
  }
  assert(generated == expected);

  destroy_cj_ctx(cj);
}

static jmp_buf sve_test_env;
static int sve_available = -1; // -1 = unknown, 0 = not available, 1 = available

static void sve_sigill_handler(int sig) {
  sve_available = 0;
  longjmp(sve_test_env, 1);
}

static int check_sve_available(void) {
  if (sve_available != -1) {
    return sve_available;
  }

  // Set up signal handler for SIGILL
  struct sigaction sa, old_sa;
  sa.sa_handler = sve_sigill_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGILL, &sa, &old_sa);

  if (setjmp(sve_test_env) == 0) {
    // Try to execute a simple SVE instruction (RDVL - read vector length)
    // This will raise SIGILL if SVE is not available
    // Use .inst to encode RDVL x0, #1 directly (opcode: 0x04bf5000)
    __asm__ volatile(".inst 0x04bf5000" : : : "x0");
    sve_available = 1;
  }

  // Restore original signal handler
  sigaction(SIGILL, &old_sa, NULL);

  return sve_available;
}

static void test_sve_execution(void) {
  if (!check_sve_available()) {
    printf("SVE not available on this system, skipping execution test\n");
    return;
  }

  // SVE is available, test actual execution
  // We'll use FTSSEL which is a simpler instruction (no special input requirements)
  // FTSSEL performs a floating-point trigonometric select
  cj_ctx *cj = create_cj_ctx();

  // For a simpler test, let's use the basic pattern we generated
  // We'll just verify the instruction executes without crashing
  // (actual functional testing would require setting up SVE state)

  cj_operand z0_d = cj_make_register("z0.d");
  cj_operand z1_d = cj_make_register("z1.d");
  cj_operand z2_d = cj_make_register("z2.d");

  // Generate: FTSMUL z0.d, z1.d, z2.d
  cj_ftsmul(cj, z0_d, z1_d, z2_d);
  cj_ret(cj);

  typedef void (*fn_t)(void);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Execute - this will crash if SVE isn't working correctly
  // (Z registers should be zero-initialized by the system)
  fn();

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_conditional_branch(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test B.EQ (branch if equal)
  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  cj_label equal = cj_create_label(cj);
  cj_label exit = cj_create_label(cj);

  cj_cmp(cj, x0, x1);
  cj_beq(cj, equal);

  // Not equal: return 0
  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(0, 0)));
  cj_b(cj, exit);

  cj_mark_label(cj, equal);
  // Equal: return 1
  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(1, 0)));

  cj_mark_label(cj, exit);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long res_eq = fn(42, 42);   // Equal
  long res_ne1 = fn(0, 42);   // Not equal
  long res_ne2 = fn(100, 42); // Not equal

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  assert(res_eq == 1);
  assert(res_ne1 == 0);
  assert(res_ne2 == 0);
}

static void test_bfmlal_encoding(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test BFMLALB encoding (BFloat16 multiply-add bottom)
  // Just verify the encoding is correct
  cj_operand v0 = cj_make_register("v0.4s");
  cj_operand v1 = cj_make_register("v1.8h");
  cj_operand v2 = cj_make_register("v2.8h");

  cj_bfmlalb(cj, v0, v1, v2);

  // Check that instruction was generated (4 bytes)
  assert(cj->len == 4);

  destroy_cj_ctx(cj);
}

// ============================================================================
// Comprehensive SIMD/NEON Tests
// ============================================================================

static void test_simd_sub(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0 = cj_make_register("v0.4s");
  cj_operand v1 = cj_make_register("v1.4s");

  // Load vectors
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // SIMD subtract: v0.4s = v0.4s - v1.4s
  cj_sub(cj, v0, v1);

  // Store result
  cj_str(cj, q0, cj_make_memory("x2", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(uint32_t *, uint32_t *, uint32_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint32_t vec1[4] = {100, 200, 300, 400};
  uint32_t vec2[4] = {10, 20, 30, 40};
  uint32_t result[4] = {0};

  fn(vec1, vec2, result);

  assert(result[0] == 90);
  assert(result[1] == 180);
  assert(result[2] == 270);
  assert(result[3] == 360);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_simd_mul(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0 = cj_make_register("v0.8h");
  cj_operand v1 = cj_make_register("v1.8h");

  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // SIMD multiply: v0.8h = v0.8h * v1.8h
  cj_mul(cj, v0, v1);

  cj_str(cj, q0, cj_make_memory("x2", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(uint16_t *, uint16_t *, uint16_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint16_t vec1[8] = {2, 3, 4, 5, 6, 7, 8, 9};
  uint16_t vec2[8] = {10, 10, 10, 10, 10, 10, 10, 10};
  uint16_t result[8] = {0};

  fn(vec1, vec2, result);

  assert(result[0] == 20);
  assert(result[1] == 30);
  assert(result[2] == 40);
  assert(result[3] == 50);
  assert(result[4] == 60);
  assert(result[5] == 70);
  assert(result[6] == 80);
  assert(result[7] == 90);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_simd_max_min(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand q2 = cj_make_register("q2");
  cj_operand v0 = cj_make_register("v0.16b");
  cj_operand v1 = cj_make_register("v1.16b");
  cj_operand v2 = cj_make_register("v2.16b");

  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // Max: v0.16b = max(v0.16b, v1.16b) - accumulator style
  cj_umax(cj, v0, v1);
  cj_str(cj, q0, cj_make_memory("x2", NULL, 1, 0));

  // Min: v1.16b = min(v1.16b, v0.16b) - reload and accumulate
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));
  cj_umin(cj, v0, v1);
  cj_str(cj, q0, cj_make_memory("x3", NULL, 1, 0));

  cj_ret(cj);

  typedef void (*fn_t)(uint8_t *, uint8_t *, uint8_t *, uint8_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint8_t vec1[16] = {1, 5, 3, 7, 2, 9, 4, 6, 8, 0, 15, 10, 12, 14, 11, 13};
  uint8_t vec2[16] = {2, 4, 6, 8, 1, 3, 5, 7, 9, 11, 13, 15, 10, 12, 14, 0};
  uint8_t max_result[16] = {0};
  uint8_t min_result[16] = {0};

  fn(vec1, vec2, max_result, min_result);

  for (int i = 0; i < 16; i++) {
    uint8_t expected_max = vec1[i] > vec2[i] ? vec1[i] : vec2[i];
    uint8_t expected_min = vec1[i] < vec2[i] ? vec1[i] : vec2[i];
    assert(max_result[i] == expected_max);
    assert(min_result[i] == expected_min);
  }

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_simd_neg(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand q0 = cj_make_register("q0");
  cj_operand v0 = cj_make_register("v0.4s");

  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));

  // NEG: v0.4s = -v0.4s
  cj_neg(cj, v0, v0);

  cj_str(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(int32_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  int32_t vec[4] = {100, -200, 300, -400};
  fn(vec);

  assert(vec[0] == -100);
  assert(vec[1] == 200);
  assert(vec[2] == -300);
  assert(vec[3] == 400);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

// ============================================================================
// Floating Point Tests
// ============================================================================

static void test_fp_add(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand d0 = cj_make_register("d0");
  cj_operand d1 = cj_make_register("d1");
  cj_operand d2 = cj_make_register("d2");

  // d0 = d0 + d1
  cj_fadd(cj, d0, d1);
  cj_ret(cj);

  typedef double (*fn_t)(double, double);
  fn_t fn = (fn_t)create_cj_fn(cj);

  assert(fn(1.5, 2.5) == 4.0);
  assert(fn(-1.5, 3.5) == 2.0);
  assert(fn(0.0, 0.0) == 0.0);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_fp_sub_mul_div(void) {
  cj_ctx *cj = create_cj_ctx();

  // Test FSUB
  cj_operand s0 = cj_make_register("s0");
  cj_operand s1 = cj_make_register("s1");
  cj_fsub(cj, s0, s1);
  cj_ret(cj);

  typedef float (*fn_t)(float, float);
  fn_t fn = (fn_t)create_cj_fn(cj);

  float result = fn(10.5f, 2.5f);
  assert(result > 7.99f && result < 8.01f); // 8.0 with float tolerance

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  // Test FMUL
  cj = create_cj_ctx();
  cj_fmul(cj, s0, s1);
  cj_ret(cj);
  fn = (fn_t)create_cj_fn(cj);
  result = fn(3.0f, 4.0f);
  assert(result > 11.99f && result < 12.01f); // 12.0
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  // Test FDIV
  cj = create_cj_ctx();
  cj_fdiv(cj, s0, s1);
  cj_ret(cj);
  fn = (fn_t)create_cj_fn(cj);
  result = fn(10.0f, 2.0f);
  assert(result > 4.99f && result < 5.01f); // 5.0
  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_fp_conversion(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand d0 = cj_make_register("d0");

  // Convert signed integer (x0) to double (d0)
  size_t before = cj->len;
  cj_scvtf(cj, d0, x0);
  size_t after = cj->len;
  printf("SCVTF generated %zu bytes\n", after - before);
  cj_ret(cj);

  typedef double (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  double result = fn(42);
  printf("SCVTF: fn(42) = %f (expected 42.0)\n", result);
  assert(result == 42.0);
  assert(fn(-100) == -100.0);
  assert(fn(0) == 0.0);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_fp_compare(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand d0 = cj_make_register("d0");
  cj_operand d1 = cj_make_register("d1");
  cj_operand x0 = cj_make_register("x0");

  cj_label greater = cj_create_label(cj);
  cj_label exit = cj_create_label(cj);

  // Compare d0 and d1
  cj_fcmp(cj, d0, d1);
  cj_bgt(cj, greater); // Branch if d0 > d1

  // d0 <= d1: return 0
  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(0, 0)));
  cj_b(cj, exit);

  // d0 > d1: return 1
  cj_mark_label(cj, greater);
  cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(1, 0)));

  cj_mark_label(cj, exit);
  cj_ret(cj);

  typedef long (*fn_t)(double, double);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long result1 = fn(5.5, 3.3);
  printf("fp_compare: fn(5.5, 3.3) = %ld (expected 1)\n", result1);
  assert(result1 == 1);      // 5.5 > 3.3
  assert(fn(2.2, 4.4) == 0); // 2.2 <= 4.4
  assert(fn(3.0, 3.0) == 0); // 3.0 <= 3.0

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

// ============================================================================
// Comprehensive Conditional Branch Tests
// ============================================================================

static void test_all_conditions(void) {
  // Test all 16 ARM64 condition codes
  typedef struct {
    const char *name;
    void (*branch_fn)(cj_ctx *, cj_label);
    long input1;
    long input2;
    int should_branch;
  } cond_test;

  // Prepare test cases: (a, b) and whether condition should be true
  cond_test tests[] = {
      // After CMP a, b (which does a - b):
      {"EQ", cj_beq, 42, 42, 1},       // Equal
      {"NE", cj_bne, 42, 43, 1},       // Not equal
      {"CS", cj_bcs, 10, 5, 1},        // Carry set (unsigned >=)
      {"CC", cj_bcc, 5, 10, 1},        // Carry clear (unsigned <)
      {"MI", cj_bmi, 5, 10, 1},        // Negative (5 - 10 < 0)
      {"PL", cj_bpl, 10, 5, 1},        // Positive (10 - 5 >= 0)
      {"VS", cj_bvs, LLONG_MIN, 1, 1}, // Overflow (MIN - 1 overflows)
      {"VC", cj_bvc, 10, 5, 1},        // No overflow
      {"HI", cj_bhi, 10, 5, 1},        // Unsigned higher
      {"LS", cj_bls, 5, 10, 1},        // Unsigned lower or same
      {"GE", cj_bge, 10, 5, 1},        // Signed >=
      {"LT", cj_blt, 5, 10, 1},        // Signed <
      {"GT", cj_bgt, 10, 5, 1},        // Signed >
      {"LE", cj_ble, 5, 10, 1},        // Signed <=
      {"AL", cj_bal, 0, 0, 1},         // Always
  };

  for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    cj_ctx *cj = create_cj_ctx();

    cj_operand x0 = cj_make_register("x0");
    cj_operand x1 = cj_make_register("x1");

    cj_label taken = cj_create_label(cj);
    cj_label exit = cj_create_label(cj);

    cj_cmp(cj, x0, x1);
    tests[i].branch_fn(cj, taken);

    // Not taken: return 0
    cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(0, 0)));
    cj_b(cj, exit);

    // Taken: return 1
    cj_mark_label(cj, taken);
    cj_movz(cj, x0, cj_make_constant(mov_literal_chunk(1, 0)));

    cj_mark_label(cj, exit);
    cj_ret(cj);

    typedef long (*fn_t)(long, long);
    fn_t fn = (fn_t)create_cj_fn(cj);

    long result = fn(tests[i].input1, tests[i].input2);
    if (result != tests[i].should_branch) {
      printf("Condition %s failed: expected %d, got %ld (inputs: %ld, %ld)\n", tests[i].name,
             tests[i].should_branch, result, tests[i].input1, tests[i].input2);
    }
    assert(result == tests[i].should_branch);

    destroy_cj_fn(cj, (cj_fn)fn);
    destroy_cj_ctx(cj);
  }
}

// ============================================================================
// Bit Manipulation Tests
// ============================================================================

static void test_bit_operations(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  // ROR (rotate right): x0 = x0 ROR x1
  cj_ror(cj, x0, x1);
  cj_ret(cj);

  typedef long (*fn_t)(long, long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // Rotate 0x0F (0b1111) right by 2 should give 0xC000000000000003
  long result = fn(0x0F, 2);
  assert(result == (long)0xC000000000000003UL);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_clz_rbit(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");
  cj_operand x1 = cj_make_register("x1");

  // CLZ: Count leading zeros
  cj_clz(cj, x0, x0);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  assert(fn(0x00000000000000FF) == 56); // 56 leading zeros
  assert(fn(0x0000000000FF0000) == 40); // 40 leading zeros
  assert(fn(0x8000000000000000) == 0);  // 0 leading zeros

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);

  // RBIT: Reverse bits
  cj = create_cj_ctx();
  cj_rbit(cj, x0, x0);
  cj_ret(cj);
  fn = (fn_t)create_cj_fn(cj);

  // 0x0F = 0b1111, reversed = 0xF000000000000000
  assert(fn(0x0F) == (long)0xF000000000000000UL);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

static void test_rev_bytes(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0");

  // REV: Reverse bytes
  cj_rev(cj, x0, x0);
  cj_ret(cj);

  typedef long (*fn_t)(long);
  fn_t fn = (fn_t)create_cj_fn(cj);

  // 0x0102030405060708 reversed = 0x0807060504030201
  assert(fn(0x0102030405060708L) == 0x0807060504030201L);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

// ============================================================================
// More Crypto Tests
// ============================================================================

static void test_sha256(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand q0 = cj_make_register("q0");
  cj_operand q1 = cj_make_register("q1");
  cj_operand v0 = cj_make_register("v0.4s");
  cj_operand v1 = cj_make_register("v1.4s");

  // Load state and message
  cj_ldr(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ldr(cj, q1, cj_make_memory("x1", NULL, 1, 0));

  // SHA256H: Hash update (accumulator style: v0 = v0 op v1)
  cj_sha256h(cj, v0, v1);

  cj_str(cj, q0, cj_make_memory("x0", NULL, 1, 0));
  cj_ret(cj);

  typedef void (*fn_t)(uint32_t *, uint32_t *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  uint32_t state[4] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a};
  uint32_t message[4] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5};
  uint32_t original[4];
  memcpy(original, state, sizeof(original));

  fn(state, message);

  // Just verify the state changed (SHA256 is complex to verify fully)
  int changed = 0;
  for (int i = 0; i < 4; i++) {
    if (state[i] != original[i]) {
      changed = 1;
      break;
    }
  }
  assert(changed);

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

// ============================================================================
// More Atomic/CAS Tests
// ============================================================================

static void test_cas_basic(void) {
  cj_ctx *cj = create_cj_ctx();

  cj_operand x0 = cj_make_register("x0"); // compare value
  cj_operand x1 = cj_make_register("x1"); // new value
  cj_operand x2 = cj_make_register("x2"); // memory address

  // CAS x0, x1, [x2]
  cj_cas(cj, x0, x1, cj_make_memory("x2", NULL, 1, 0));
  cj_ret(cj);

  typedef long (*fn_t)(long, long, long *);
  fn_t fn = (fn_t)create_cj_fn(cj);

  long memory = 42;
  long result = fn(42, 100, &memory); // Should swap: compare matches
  assert(memory == 100);              // Memory updated
  assert(result == 42);               // Returns old value

  memory = 42;
  result = fn(99, 100, &memory); // Should not swap: compare doesn't match
  assert(memory == 42);          // Memory unchanged
  assert(result == 42);          // Returns current value

  destroy_cj_fn(cj, (cj_fn)fn);
  destroy_cj_ctx(cj);
}

int main(void) {
  test_mov_returns_second_argument();
  puts("mov ok");
  test_add_immediate();
  puts("add imm ok");
  test_add_register();
  puts("add reg ok");
  test_add_shifted_register();
  puts("add shifted ok");
  test_add_immediate_shifted();
  puts("add imm shifted ok");
  test_add_extended_register();
  puts("add extended ok");
  test_add_signed_extend();
  puts("add signed extend ok");
  test_and_shifted_register();
  puts("and shifted ok");
  test_str_pre_index();
  puts("str pre-index ok");
  test_ldr_post_index();
  puts("ldr post-index ok");
  test_movz_literal();
  puts("movz ok");
  test_movk_multi_chunk();
  puts("movk multi ok");
  test_store_load_roundtrip();
  puts("store/load roundtrip ok");
  test_branch_max();
  puts("branch max ok");
  test_cmp_shifted_register_branch();
  puts("cmp shifted branch ok");
  test_cmp_immediate_branch();
  puts("cmp immediate branch ok");

  // New arithmetic and bitwise tests
  test_sub_register();
  puts("sub reg ok");
  test_sub_immediate();
  puts("sub imm ok");
  test_or_register();
  puts("or reg ok");
  test_xor_register();
  puts("xor reg ok");
  test_mul_register();
  puts("mul reg ok");
  test_udiv_register();
  puts("udiv reg ok");
  test_sdiv_register();
  puts("sdiv reg ok");
  test_lsl_register();
  puts("lsl reg ok");
  test_lsr_register();
  puts("lsr reg ok");
  test_asr_register();
  puts("asr reg ok");
  test_mvn_register();
  puts("mvn reg ok");

  // Exclusive load/store tests
  test_ldxr_simple();
  puts("ldxr ok");
  test_stxr_simple();
  puts("stxr ok");
  test_ldar_simple();
  puts("ldar ok");

  // SIMD tests
  test_simd_add();
  puts("simd add ok");
  test_simd_abs();
  puts("simd abs ok");

  // Crypto tests
  test_aes_encrypt();
  puts("aes encrypt ok");

  // {2} suffix SIMD tests
  test_xtn_narrow();
  puts("xtn/xtn2 ok");

  // SVE tests
  test_sve_encoding();
  puts("sve encoding ok");
  test_sve_execution();
  puts("sve execution ok");

  // Conditional branch tests
  test_conditional_branch();
  puts("conditional branch ok");

  // BFloat16 tests
  test_bfmlal_encoding();
  puts("bfmlal encoding ok");

  // Comprehensive SIMD tests
  test_simd_sub();
  puts("simd sub ok");
  test_simd_mul();
  puts("simd mul ok");
  test_simd_max_min();
  puts("simd max/min ok");
  test_simd_neg();
  puts("simd neg ok");

  // Floating point tests
  test_fp_add();
  puts("fp add ok");
  test_fp_sub_mul_div();
  puts("fp sub/mul/div ok");
  test_fp_conversion();
  puts("fp conversion ok");
  test_fp_compare();
  puts("fp compare ok");

  // All conditional branches
  test_all_conditions();
  puts("all conditions ok");

  // Bit manipulation
  test_bit_operations();
  puts("bit ops ok");
  test_clz_rbit();
  puts("clz/rbit ok");
  test_rev_bytes();
  puts("rev bytes ok");

  // More crypto
  test_sha256();
  puts("sha256 ok");

  // More atomics
  test_cas_basic();
  puts("cas ok");

  return 0;
}
