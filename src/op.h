#pragma once

#include "ctx.h"

typedef enum {
  CJ_REGISTER,
  CJ_CONSTANT,
  CJ_MEMORY,
  CJ_REGISTER_LIST
} cj_operand_type;

typedef enum {
  CJ_SHIFT_KIND_NONE = 0,
  CJ_SHIFT_KIND_LSL,
  CJ_SHIFT_KIND_LSR,
  CJ_SHIFT_KIND_ASR,
  CJ_SHIFT_KIND_ROR
} cj_shift_kind;

typedef enum {
  CJ_EXTEND_KIND_NONE = 0,
  CJ_EXTEND_KIND_UXTB,
  CJ_EXTEND_KIND_UXTH,
  CJ_EXTEND_KIND_UXTW,
  CJ_EXTEND_KIND_UXTX,
  CJ_EXTEND_KIND_SXTB,
  CJ_EXTEND_KIND_SXTH,
  CJ_EXTEND_KIND_SXTW,
  CJ_EXTEND_KIND_SXTX
} cj_extend_kind;

typedef enum {
  CJ_MEM_MODE_OFFSET = 0,
  CJ_MEM_MODE_PRE,
  CJ_MEM_MODE_POST
} cj_mem_mode;

typedef struct {
  uint8_t kind;       // cj_shift_kind
  uint8_t amount;     // Shift amount (bits depend on instruction)
  uint8_t has_amount; // Explicit amount provided
} cj_shift_info;

typedef struct {
  uint8_t kind;       // cj_extend_kind
  uint8_t amount;     // Optional left shift applied after extend
  uint8_t has_amount; // Explicit shift amount provided
} cj_extend_info;

typedef enum {
  CJ_ROUND_DEFAULT = 0,
  CJ_ROUND_NEAREST,
  CJ_ROUND_DOWN,
  CJ_ROUND_UP,
  CJ_ROUND_ZERO
} cj_rounding_mode;

typedef struct {
  cj_operand_type type;
  const char* mask;
  uint8_t zero_mask;
  uint8_t sae;
  uint8_t rounding;
  union {
    const char* reg;
    uint64_t constant;
    struct {
      const char* base;
      const char* index;
      uint8_t scale;
      int32_t disp;
      cj_mem_mode mode;
    } mem;
    struct {
      const char* const* regs;
      uint8_t count;
    } reg_list;
  };
  cj_shift_info shift;
  cj_extend_info extend;
} cj_operand;

static inline cj_operand cj_make_register(const char* name) {
  cj_operand op = {
      .type = CJ_REGISTER,
      .mask = NULL,
      .zero_mask = 0,
      .sae = 0,
      .rounding = CJ_ROUND_DEFAULT,
      .reg = name,
      .shift = {.kind = CJ_SHIFT_KIND_NONE, .amount = 0, .has_amount = 0},
      .extend = {.kind = CJ_EXTEND_KIND_NONE, .amount = 0, .has_amount = 0},
  };
  return op;
}

static inline cj_operand cj_make_constant(uint64_t value) {
  cj_operand op = {
      .type = CJ_CONSTANT,
      .mask = NULL,
      .zero_mask = 0,
      .sae = 0,
      .rounding = CJ_ROUND_DEFAULT,
      .constant = value,
      .shift = {.kind = CJ_SHIFT_KIND_NONE, .amount = 0, .has_amount = 0},
      .extend = {.kind = CJ_EXTEND_KIND_NONE, .amount = 0, .has_amount = 0},
  };
  return op;
}

static inline cj_operand cj_make_memory(const char* base, const char* index, uint8_t scale, int32_t disp) {
  cj_operand op = {
      .type = CJ_MEMORY,
      .mask = NULL,
      .zero_mask = 0,
      .sae = 0,
      .rounding = CJ_ROUND_DEFAULT,
      .mem = {.base = base, .index = index, .scale = scale, .disp = disp, .mode = CJ_MEM_MODE_OFFSET},
      .shift = {.kind = CJ_SHIFT_KIND_NONE, .amount = 0, .has_amount = 0},
      .extend = {.kind = CJ_EXTEND_KIND_NONE, .amount = 0, .has_amount = 0},
  };
  return op;
}

static inline cj_operand cj_make_preindexed(const char* base, int32_t disp) {
  cj_operand op = cj_make_memory(base, NULL, 1, disp);
  op.mem.mode = CJ_MEM_MODE_PRE;
  return op;
}

static inline cj_operand cj_make_postindexed(const char* base, int32_t disp) {
  cj_operand op = cj_make_memory(base, NULL, 1, disp);
  op.mem.mode = CJ_MEM_MODE_POST;
  return op;
}

static inline cj_operand cj_make_reg_list(const char* const* regs, uint8_t count) {
  cj_operand op = {
      .type = CJ_REGISTER_LIST,
      .mask = NULL,
      .zero_mask = 0,
      .sae = 0,
      .rounding = CJ_ROUND_DEFAULT,
      .reg_list = {.regs = regs, .count = count},
      .shift = {.kind = CJ_SHIFT_KIND_NONE, .amount = 0, .has_amount = 0},
      .extend = {.kind = CJ_EXTEND_KIND_NONE, .amount = 0, .has_amount = 0},
  };
  return op;
}

static inline cj_operand cj_apply_shift(cj_operand base, cj_shift_kind kind, int amount) {
  if (kind == CJ_SHIFT_KIND_NONE) {
    base.shift.kind = CJ_SHIFT_KIND_NONE;
    base.shift.amount = 0;
    base.shift.has_amount = 0;
    return base;
  }
  base.shift.kind = kind;
  if (amount >= 0) {
    base.shift.amount = (uint8_t)amount;
    base.shift.has_amount = 1;
  } else {
    base.shift.amount = 0;
    base.shift.has_amount = 0;
  }
  return base;
}

static inline cj_operand cj_apply_extend(cj_operand base, cj_extend_kind kind, int amount) {
  if (kind == CJ_EXTEND_KIND_NONE) {
    base.extend.kind = CJ_EXTEND_KIND_NONE;
    base.extend.amount = 0;
    base.extend.has_amount = 0;
    return base;
  }
  base.extend.kind = kind;
  if (amount >= 0) {
    base.extend.amount = (uint8_t)amount;
    base.extend.has_amount = 1;
  } else {
    base.extend.amount = 0;
    base.extend.has_amount = 0;
  }
  return base;
}

static inline cj_operand cj_operand_lsl(cj_operand base, int amount) {
  return cj_apply_shift(base, CJ_SHIFT_KIND_LSL, amount);
}

static inline cj_operand cj_operand_lsr(cj_operand base, int amount) {
  return cj_apply_shift(base, CJ_SHIFT_KIND_LSR, amount);
}

static inline cj_operand cj_operand_asr(cj_operand base, int amount) {
  return cj_apply_shift(base, CJ_SHIFT_KIND_ASR, amount);
}

static inline cj_operand cj_operand_ror(cj_operand base, int amount) {
  return cj_apply_shift(base, CJ_SHIFT_KIND_ROR, amount);
}

static inline cj_operand cj_operand_uxtw(cj_operand base, int amount) {
  return cj_apply_extend(base, CJ_EXTEND_KIND_UXTW, amount);
}

static inline cj_operand cj_operand_uxtx(cj_operand base, int amount) {
  return cj_apply_extend(base, CJ_EXTEND_KIND_UXTX, amount);
}

static inline cj_operand cj_operand_sxtw(cj_operand base, int amount) {
  return cj_apply_extend(base, CJ_EXTEND_KIND_SXTW, amount);
}

static inline cj_operand cj_operand_sxtx(cj_operand base, int amount) {
  return cj_apply_extend(base, CJ_EXTEND_KIND_SXTX, amount);
}

typedef enum {
  CJ_COND_O,
  CJ_COND_NO,
  CJ_COND_B,
  CJ_COND_NB,
  CJ_COND_Z,
  CJ_COND_NZ,
  CJ_COND_BE,
  CJ_COND_A,
  CJ_COND_S,
  CJ_COND_NS,
  CJ_COND_P,
  CJ_COND_NP,
  CJ_COND_L,
  CJ_COND_GE,
  CJ_COND_LE,
  CJ_COND_G,
  CJ_COND_E = CJ_COND_Z,
  CJ_COND_NE = CJ_COND_NZ,
  CJ_COND_AE = CJ_COND_NB,
  CJ_COND_NA = CJ_COND_BE,
  CJ_COND_PE = CJ_COND_P,
  CJ_COND_PO = CJ_COND_NP
} cj_condition;

#define CJ_REG(NAME) \
  static const cj_operand cj_##NAME = (cj_operand){ \
    .type = CJ_REGISTER, \
    .mask = NULL, \
    .zero_mask = 0, \
    .sae = 0, \
    .rounding = CJ_ROUND_DEFAULT, \
    .reg = #NAME, \
    .shift = {.kind = CJ_SHIFT_KIND_NONE, .amount = 0, .has_amount = 0}, \
    .extend = {.kind = CJ_EXTEND_KIND_NONE, .amount = 0, .has_amount = 0} \
  }

#if defined(__x86_64__) || defined(_M_X64)
#include "arch/x86_64/backend.h"
#elif defined(__aarch64__) || defined(_M_ARM64)
#include "arch/arm64/backend.h"
#else
#error "Unsupported architecture"
#endif
