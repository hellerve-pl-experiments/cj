#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../ctx.h"
#include "../../op.h"

static inline int arm64_parse_reg(const char* name) {
  if (!name) return -1;

  for (int i = 0; i <= 30; i++) {
    char buf[8];
    snprintf(buf, sizeof(buf), "x%d", i);
    if (strcmp(name, buf) == 0) return i;
  }

  for (int i = 0; i <= 30; i++) {
    char buf[8];
    snprintf(buf, sizeof(buf), "w%d", i);
    if (strcmp(name, buf) == 0) return i;
  }

  if (strcmp(name, "xzr") == 0) return 31;
  if (strcmp(name, "wzr") == 0) return 31;
  if (strcmp(name, "sp") == 0) return 31;

  return -1;
}

static inline int arm64_is_64bit(const char* name) {
  if (!name) return 0;
  return name[0] == 'x' || strcmp(name, "sp") == 0;
}

static inline int arm64_parse_fp_reg(const char* name) {
  if (!name) return -1;

  for (int i = 0; i <= 31; i++) {
    char buf[8];
    snprintf(buf, sizeof(buf), "s%d", i);
    if (strcmp(name, buf) == 0) return i;
  }

  for (int i = 0; i <= 31; i++) {
    char buf[8];
    snprintf(buf, sizeof(buf), "d%d", i);
    if (strcmp(name, buf) == 0) return i;
  }

  return -1;
}

static inline int arm64_is_fp_64bit(const char* name) {
  if (!name) return 0;
  return name[0] == 'd';
}

typedef struct {
  int reg;
  uint32_t q;
  uint32_t size;
} arm64_vec_reg_info;

static inline arm64_vec_reg_info arm64_parse_vec_reg(const char* name) {
  arm64_vec_reg_info info = { .reg = -1, .q = 0, .size = 0 };
  if (!name || name[0] != 'v') return info;

  const char* ptr = name + 1;
  int reg = 0;
  while (*ptr >= '0' && *ptr <= '9') {
    reg = reg * 10 + (*ptr - '0');
    ptr++;
  }
  if (ptr == name + 1 || reg < 0 || reg > 31) {
    info.reg = -1;
    return info;
  }
  info.reg = reg;

  uint32_t q = 1;
  uint32_t size = 0;

  if (*ptr == '.') {
    ptr++;
    if (ptr[0] == '8' && ptr[1] == 'b') {
      size = 0;
      q = 0;
      ptr += 2;
    } else if (ptr[0] == '1' && ptr[1] == '6' && ptr[2] == 'b') {
      size = 0;
      q = 1;
      ptr += 3;
    } else if (ptr[0] == '4' && ptr[1] == 'h') {
      size = 1;
      q = 0;
      ptr += 2;
    } else if (ptr[0] == '8' && ptr[1] == 'h') {
      size = 1;
      q = 1;
      ptr += 2;
    } else if (ptr[0] == '2' && ptr[1] == 's') {
      size = 2;
      q = 0;
      ptr += 2;
    } else if (ptr[0] == '4' && ptr[1] == 's') {
      size = 2;
      q = 1;
      ptr += 2;
    } else if (ptr[0] == '1' && ptr[1] == 'd') {
      size = 3;
      q = 0;
      ptr += 2;
    } else if (ptr[0] == '2' && ptr[1] == 'd') {
      size = 3;
      q = 1;
      ptr += 2;
    } else {
      info.reg = -1;
      return info;
    }
  }

  info.q = q;
  info.size = size;
  return info;
}

static inline int arm64_parse_q_reg(const char* name) {
  if (!name || name[0] != 'q') return -1;

  const char* ptr = name + 1;
  int reg = 0;
  while (*ptr >= '0' && *ptr <= '9') {
    reg = reg * 10 + (*ptr - '0');
    ptr++;
  }
  if (ptr == name + 1 || *ptr != '\0' || reg < 0 || reg > 31) {
    return -1;
  }
  return reg;
}

typedef struct {
  int reg;
  uint32_t size;
} arm64_z_reg_info;

static inline arm64_z_reg_info arm64_parse_z_reg(const char* name) {
  arm64_z_reg_info info = { .reg = -1, .size = 0 };
  if (!name || name[0] != 'z') return info;

  const char* ptr = name + 1;
  int reg = 0;
  while (*ptr >= '0' && *ptr <= '9') {
    reg = reg * 10 + (*ptr - '0');
    ptr++;
  }
  if (ptr == name + 1 || reg < 0 || reg > 31) {
    info.reg = -1;
    return info;
  }
  info.reg = reg;

  uint32_t size = 0;
  if (*ptr == '.') {
    ptr++;
    if (*ptr == 'b' || *ptr == 'B') {
      size = 0;
      ptr++;
    } else if (*ptr == 'h' || *ptr == 'H') {
      size = 1;
      ptr++;
    } else if (*ptr == 's' || *ptr == 'S') {
      size = 2;
      ptr++;
    } else if (*ptr == 'd' || *ptr == 'D') {
      size = 3;
      ptr++;
    } else {
      info.reg = -1;
      return info;
    }
  }

  if (*ptr != '\0') {
    info.reg = -1;
    return info;
  }

  info.size = size;
  return info;
}

static inline int arm64_parse_p_reg(const char* name) {
  if (!name || name[0] != 'p') return -1;

  const char* ptr = name + 1;
  int reg = 0;
  while (*ptr >= '0' && *ptr <= '9') {
    reg = reg * 10 + (*ptr - '0');
    ptr++;
  }
  if (ptr == name + 1 || reg < 0 || reg > 15) {
    return -1;
  }

  if (*ptr == '/' && (ptr[1] == 'm' || ptr[1] == 'z')) {
    ptr += 2;
  }

  if (*ptr != '\0') {
    return -1;
  }

  return reg;
}

typedef struct {
  arm64_vec_reg_info regs[4];
  uint8_t count;
} arm64_vec_list_info;

static inline int arm64_parse_vec_list_operand(cj_operand operand, uint8_t expected_count, arm64_vec_list_info* out) {
  if (!out || expected_count == 0 || expected_count > 4) return 0;
  out->count = 0;

  if (operand.type == CJ_REGISTER) {
    if (expected_count != 1) return 0;
    arm64_vec_reg_info info = arm64_parse_vec_reg(operand.reg);
    if (info.reg < 0) return 0;
    out->regs[0] = info;
    out->count = 1;
    return 1;
  }

  if (operand.type != CJ_REGISTER_LIST || !operand.reg_list.regs || operand.reg_list.count != expected_count) {
    return 0;
  }

  for (uint8_t i = 0; i < expected_count; ++i) {
    arm64_vec_reg_info info = arm64_parse_vec_reg(operand.reg_list.regs[i]);
    if (info.reg < 0) return 0;
    if (i > 0) {
      const arm64_vec_reg_info prev = out->regs[i - 1];
      if (info.q != prev.q || info.size != prev.size) return 0;
      if (((prev.reg + 1) & 0x1f) != info.reg) return 0;
    }
    out->regs[i] = info;
  }

  out->count = expected_count;
  return 1;
}

static inline void cj_abs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E20B800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_adc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_adcs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x3A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_add(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E208400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0B000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 12) - 1u);
    if (imm > 4095) return;
    uint32_t instr = 0x11000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr |= ((imm & 0xfff) << 10);
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0B200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_addg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_addp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E20BC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_addpl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x04605000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 5);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_adds(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x2B000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 12) - 1u);
    if (imm > 4095) return;
    uint32_t instr = 0x31000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr |= ((imm & 0xfff) << 10);
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x2B200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_addv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_addvl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x04205000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 5);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_adr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_adrp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_aesd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x4E285800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_aese(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x4E284800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_aesimc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x4E287800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_aesmc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x4E286800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_and(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E201C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x12000000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ands(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x6A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x72000000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_andv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_asr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02800;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x13007C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_asrd(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04048000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_asrr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04148000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_asrv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02800;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_at(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_autda(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11800;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autdza(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autdb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autdzb(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11C00;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autia(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autiza(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11000;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autia1716(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503219F);
}

static inline void cj_autiasp(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503219F);
}

static inline void cj_autiaz(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503219F);
}

static inline void cj_autib(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11400;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autizb(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC11400;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_autib1716(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50321DF);
}

static inline void cj_autibsp(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50321DF);
}

static inline void cj_autibz(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50321DF);
}

static inline void cj_axflag(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD500405F);
}

static inline void cj_bcax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE200000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_bfcvt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E634000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfcvtn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0EA16800;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfcvtn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0EA16800;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfcvtnt(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x648AA000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfdot(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E40FC00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_bfi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_bfm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x33000000;
    instr = arm64_is_64bit(dst.reg) ? 0x33000000 : 0x33000000;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfmlalb(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    uint32_t instr = 0x2EC0FC00;
    instr &= ~(1u << 30);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfmlalt(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    uint32_t instr = 0x2EC0FC00;
    instr |= (1u << 30);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bfmmla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x6E40EC00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_bfxil(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_bic(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E601C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0A200000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bics(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x6A200000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bif(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2EE01C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bit(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2EA01C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_blr(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD63F0000;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_blraaz(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD63F0800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_blraa(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD63F0800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_blrabz(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD63F0800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_blrab(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD63F0800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_br(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD61F0000;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_braaz(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD61F0800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_braa(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD61F0800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_brabz(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD61F0800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_brab(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD61F0800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_brk(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_brka(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkas(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkbs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkns(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkpa(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkpas(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkpb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_brkpbs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_bsl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E601C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_bti(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_cas(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casa(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casal(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casl(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casab(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casalb(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casb(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_caslb(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casah(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casalh(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cash(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_caslh(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {
  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(compare.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48A07C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_casp(cj_ctx* ctx, cj_operand cmp1, cj_operand cmp2, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (cmp1.type == CJ_REGISTER && cmp2.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(cmp1.reg);
    if (rs < 0 || (rs & 1) != 0) return;
    int rs2 = arm64_parse_reg(cmp2.reg);
    if (rs2 != rs + 1) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(val1.reg);
    
    uint32_t instr = is64 ? 0x08207C00 : 0x08207C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_caspa(cj_ctx* ctx, cj_operand cmp1, cj_operand cmp2, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (cmp1.type == CJ_REGISTER && cmp2.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(cmp1.reg);
    if (rs < 0 || (rs & 1) != 0) return;
    int rs2 = arm64_parse_reg(cmp2.reg);
    if (rs2 != rs + 1) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(val1.reg);
    
    uint32_t instr = is64 ? 0x08207C00 : 0x08207C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_caspal(cj_ctx* ctx, cj_operand cmp1, cj_operand cmp2, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (cmp1.type == CJ_REGISTER && cmp2.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(cmp1.reg);
    if (rs < 0 || (rs & 1) != 0) return;
    int rs2 = arm64_parse_reg(cmp2.reg);
    if (rs2 != rs + 1) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(val1.reg);
    
    uint32_t instr = is64 ? 0x08207C00 : 0x08207C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_caspl(cj_ctx* ctx, cj_operand cmp1, cj_operand cmp2, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (cmp1.type == CJ_REGISTER && cmp2.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(cmp1.reg);
    if (rs < 0 || (rs & 1) != 0) return;
    int rs2 = arm64_parse_reg(cmp2.reg);
    if (rs2 != rs + 1) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(val1.reg);
    
    uint32_t instr = is64 ? 0x08207C00 : 0x08207C00;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ccmn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 5) - 1u);
    uint32_t instr = 0x3A400800;
    instr = arm64_is_64bit(dst.reg) ? 0xBA400800 : 0x3A400800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((uint32_t)(imm & ((1u << 5) - 1u))) << 16;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ccmp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 5) - 1u);
    uint32_t instr = 0x7A400800;
    instr = arm64_is_64bit(dst.reg) ? 0xFA400800 : 0x7A400800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((uint32_t)(imm & ((1u << 5) - 1u))) << 16;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cfinv(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD500401F);
}

static inline void cj_cfp(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_cinc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cinv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_clasta(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_clastb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_clrex(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_cls(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E204800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5AC01400;
    instr = arm64_is_64bit(dst.reg) ? 0xDAC01400 : 0x5AC01400;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_clz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E204800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5AC01000;
    instr = arm64_is_64bit(dst.reg) ? 0xDAC01000 : 0x5AC01000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmeq(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E208C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmge(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E203C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmgt(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E203400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmhi(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E203400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmhs(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E203C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmle(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E209800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmlt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E20A800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x2B00001F;
    instr = arm64_is_64bit(dst.reg) ? 0xAB00001F : 0x2B00001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 12) - 1u);
    uint32_t instr = 0x3100001F;
    instr = arm64_is_64bit(dst.reg) ? 0xB100001F : 0x3100001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 12) - 1u) << 10);
    instr |= ((uint32_t)(imm & ((1u << 12) - 1u))) << 10;
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x2B20001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x6B00001F;
    instr = arm64_is_64bit(dst.reg) ? 0xEB00001F : 0x6B00001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 12) - 1u);
    uint32_t instr = 0x7100001F;
    instr = arm64_is_64bit(dst.reg) ? 0xF100001F : 0x7100001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 12) - 1u) << 10);
    instr |= ((uint32_t)(imm & ((1u << 12) - 1u))) << 10;
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x6B20001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmpeq(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmpgt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmpge(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmphi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmphs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmplt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmple(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmplo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmpls(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmpne(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cmpp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xBAC0001F;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cmtst(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E208C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cneg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cnot(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x041BA000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cnt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E205800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cntb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cntd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cnth(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cntw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_cntp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_compact(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x05218000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cpp(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_cpy(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_crc32b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC04000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC04000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC04000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32x(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC04000;
    instr |= (1 << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32cb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC05000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32ch(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC05000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32cw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC05000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_crc32cx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC05000;
    instr |= (1 << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_csdb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503229F);
}

static inline void cj_csel(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1A800000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_cset(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_csetm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_csinc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1A800400;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_csinv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5A800000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_csneg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5A800400;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ctermeq(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ctermne(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dcps1(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_dcps2(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_dcps3(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_decb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_decd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dech(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_decw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_decp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dfb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD5033C9F);
}

static inline void cj_dgh(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50320DF);
}

static inline void cj_dmb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_drps(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD6BF03E0);
}

static inline void cj_dsb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dup(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dupm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_dvp(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_eon(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x4A200000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_eor3(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE000000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_eor(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E201C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x4A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x52000000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_eors(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_eorv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_eret(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD69F03E0);
}

static inline void cj_eretaa(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD69F0BFF);
}

static inline void cj_eretab(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD69F0FFF);
}

static inline void cj_esb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503221F);
}

static inline void cj_ext(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_extr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x13800000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fabd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2EC01400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7EC01400;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fabs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF8F800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE0C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_facge(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E402C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7E402C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_facgt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2EC02C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7EC02C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_facle(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_faclt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E401400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE02800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fadda(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_faddp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E401400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_faddv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fcadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E00E400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_fccmp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fccmpe(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fcmeq(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF8D800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E402400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5E402400;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5EF8D800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmgt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF8C800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2EC02400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7EC02400;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5EF8C800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmge(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF8C800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E402400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7E402400;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7EF8C800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmlt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0EF8E800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmle(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2EF8D800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmne(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fcmuo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fcmla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E00C400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_fcmp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E202000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcmpe(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E202010;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcpy(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fcsel(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE00C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E224000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtas(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E79C800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5E79C800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E240000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtau(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E79C800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7E79C800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E250000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E217800;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtl2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E217800;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtms(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E79B800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5E79B800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E300000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtmu(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E79B800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7E79B800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E310000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E216800;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E216800;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtns(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E79A800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5E79A800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtnu(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E79A800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7E79A800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E210000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtps(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF9A800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5EF9A800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E280000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtpu(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF9A800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7EF9A800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E290000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtxn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E216800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtzs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF9B800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5EF9B800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E380000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fcvtzu(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF9B800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7EF9B800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E390000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fdiv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E403C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE01800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fdivr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x650C8000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fdup(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fexpa(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fjcvtzs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E7E0000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmad(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65208000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1FC00000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E403400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE04800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmaxnm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E400400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE06800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmaxnmp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E400400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmaxnmv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fmaxp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E403400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmaxv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fmin(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EC03400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE05800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fminnm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EC00400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE07800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fminnmp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2EC00400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fminnmv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fminp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2EC03400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fminv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_fmla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E400C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_fmlal(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E20EC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmlal2(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E20CC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmls(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EC00C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_fmlsl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0EA0EC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmlsl2(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2EA0CC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmmla(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x64A0E400;
    instr |= ((zd.size & 0x3) << 22);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmov(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE04000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E260000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 'x' || src.reg[0] == 'w')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E260000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    int sf = arm64_is_64bit(src.reg) ? 1 : 0;
    instr &= ~(1u << 31);
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 8) - 1u);
    uint32_t instr = 0x1EE01000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 8) - 1u) << 13);
    instr |= ((uint32_t)(imm & ((1u << 8) - 1u))) << 13;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmsb(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x6520A000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmsub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1FC08000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmul(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E401C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE00800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fmulx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E401C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5E401C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fneg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF8F800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE14000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmad(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x6520C000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1FE00000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmla(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65204000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmls(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65206000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmsb(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x6520E000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmsub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1FE08000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fnmul(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE08800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frecpe(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0EF9D800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frecps(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E403C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5E403C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frecpx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x5EF9F800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frint32x(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E21E800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E28C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frint32z(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E21E800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E284000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frint64x(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E21F800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E29C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frint64z(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E21F800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E294000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frinta(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E798800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE64000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frinti(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF99800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE7C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frintx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E799800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE74000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frintn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E798800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE44000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frintz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF99800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE5C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frintm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E799800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE54000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frintp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0EF98800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE4C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frsqrte(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2EF9D800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_frsqrts(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EC03C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5EC03C00;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fscale(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65098000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fsqrt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2EF9F800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1EE1C000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fsub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EC01400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_fp_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1EE03800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_fsubr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x651B8000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ftmad(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65108000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ftsmul(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x65000C00;
    instr |= ((zd.size & 0x3) << 22);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ftssel(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x0420B000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_gmi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9AC01400;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_hint(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_hlt(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_hvc(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_ic(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_incb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_incd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_inch(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_incw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_incp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_index(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ins(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_insr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_irg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9AC01000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_isb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_lasta(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_lastb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C407000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 2, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C40A000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C40A000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 3, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C406000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C406000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 4, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C402000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C402000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC02000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC02000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC02000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC02000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1r(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0D40C000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0DC0C000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld1rb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rob(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rod(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1roh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1row(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rqb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rqd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rqh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rqw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rsb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rsh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rsw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1rw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1sb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1sh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1sw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 2, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C408000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C408000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC08000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld2b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld2d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld2h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld2r(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 2, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0D60C000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0D60C000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0DE0C000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld2w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld3(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 3, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C404000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C404000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC04000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld3b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld3d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld3h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld3r(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 3, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0D40E000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0D40E000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0DC0E000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld3w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld4(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 4, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C400000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0CC00000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld4b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld4d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld4h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ld4r(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 4, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0D60E000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0D60E000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0DE0E000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ld4w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldadd(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8200000 : 0xB8200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldadda(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A00000 : 0xB8A00000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E00000 : 0xB8E00000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8600000 : 0xB8600000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaddlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78200000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0xB8A0C000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaprb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38A0C000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaprh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78A0C000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapur(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x99400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapurb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x19400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapurh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x59400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapursb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x19C00000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapursh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x59C00000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldapursw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x99800000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldar(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(dst.reg);
    
    uint32_t instr = is64 ? 0xC8C08000 : 0x88C08000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldarb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08C08000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldarh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48C08000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaxp(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88608000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaxr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(dst.reg);
    
    uint32_t instr = is64 ? 0xC8408000 : 0x88408000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaxrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08408000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldaxrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48408000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclr(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8201000 : 0xB8201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclra(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A01000 : 0xB8A01000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclral(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E01000 : 0xB8E01000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8601000 : 0xB8601000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclralb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclralh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldclrlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78201000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeor(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8202000 : 0xB8202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeora(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A02000 : 0xB8A02000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeoral(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E02000 : 0xB8E02000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8602000 : 0xB8602000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeoralb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeoralh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldeorlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78202000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldff1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1sb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1sh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1sw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldff1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xD9600000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldgm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD9E00000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldlar(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(dst.reg);
    
    uint32_t instr = is64 ? 0xC8C00000 : 0x88C00000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldlarb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08C00000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldlarh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48C00000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldnf1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1sb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1sh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1sw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnf1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnp(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {
  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg1 = arm64_parse_reg(rt1.reg);
    if (reg1 < 0) return;
    int reg2 = arm64_parse_reg(rt2.reg);
    if (reg2 < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    int32_t offset = mem.mem.disp;
    
    int is64 = arm64_is_64bit(rt1.reg);
    int scale = is64 ? 8 : 4;
    
    if ((offset % scale) != 0) return;
    int32_t imm7 = offset / scale;
    if (imm7 < -64 || imm7 > 63) return;
    
    uint32_t instr = is64 ? 0xA9400000 : 0x29400000;
    
    instr |= (reg1 & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg2 & 0x1f) << 10);
    instr |= ((imm7 & 0x7f) << 15);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldnt1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnt1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnt1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldnt1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ldp(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {
  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg1 = arm64_parse_reg(rt1.reg);
    if (reg1 < 0) return;
    int reg2 = arm64_parse_reg(rt2.reg);
    if (reg2 < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    int32_t offset = mem.mem.disp;
    
    int is64 = arm64_is_64bit(rt1.reg);
    int scale = is64 ? 8 : 4;
    
    if ((offset % scale) != 0) return;
    int32_t imm7 = offset / scale;
    if (imm7 < -64 || imm7 > 63) return;
    
    uint32_t instr = is64 ? 0xA9400000 : 0x29400000;
    
    instr |= (reg1 & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg2 & 0x1f) << 10);
    instr |= ((imm7 & 0x7f) << 15);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldpsw(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {
  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg1 = arm64_parse_reg(rt1.reg);
    if (reg1 < 0) return;
    int reg2 = arm64_parse_reg(rt2.reg);
    if (reg2 < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    int32_t offset = mem.mem.disp;
    
    int is64 = arm64_is_64bit(rt1.reg);
    int scale = is64 ? 8 : 4;
    
    if ((offset % scale) != 0) return;
    int32_t imm7 = offset / scale;
    if (imm7 < -64 || imm7 > 63) return;
    
    uint32_t instr = is64 ? 0xA9400000 : 0x29400000;
    
    instr |= (reg1 & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg2 & 0x1f) << 10);
    instr |= ((imm7 & 0x7f) << 15);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int qt = arm64_parse_q_reg(dst.reg);
    if (qt >= 0 && src.mem.mode == CJ_MEM_MODE_OFFSET && !src.mem.index) {
      const char* base = src.mem.base ? src.mem.base : "sp";
      int rn = arm64_parse_reg(base);
      if (rn < 0) return;
      int64_t offset = src.mem.disp;
      if (offset % 16 != 0) return;
      uint64_t imm12 = offset / 16;
      if (imm12 > 4095) return;
      uint32_t instr = 0x3DC00000;
      instr |= ((imm12 & 0xfff) << 10);
      instr |= ((rn & 0x1f) << 5);
      instr |= (qt & 0x1f);
      cj_add_u32(ctx, instr);
      return;
    }
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8600800 : 0xB8600800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF9400000 : 0xB9400000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int qt = arm64_parse_q_reg(dst.reg);
    if (qt >= 0 && src.mem.mode == CJ_MEM_MODE_OFFSET && !src.mem.index) {
      const char* base = src.mem.base ? src.mem.base : "sp";
      int rn = arm64_parse_reg(base);
      if (rn < 0) return;
      int64_t offset = src.mem.disp;
      if (offset % 16 != 0) return;
      uint64_t imm12 = offset / 16;
      if (imm12 > 4095) return;
      uint32_t instr = 0x3DC00000;
      instr |= ((imm12 & 0xfff) << 10);
      instr |= ((rn & 0x1f) << 5);
      instr |= (qt & 0x1f);
      cj_add_u32(ctx, instr);
      return;
    }
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8600800 : 0xB8600800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = (arm64_is_64bit(dst.reg) ? 0xF8400C00 : 0xB8400C00);
      } else {
        instr = (arm64_is_64bit(dst.reg) ? 0xF8400400 : 0xB8400400);
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8400400 : 0xB8400400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xB8600800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xF8600800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldraa(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = 0xF8200400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
}

static inline void cj_ldrab(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    uint64_t imm12 = offset;
    if (imm12 > 4095) return;
    uint32_t instr = 0xF8200400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
}

static inline void cj_ldrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = 0x39400000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = 0x38400C00;
      } else {
        instr = 0x38400400;
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = 0x38400400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38600800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38606800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0x78600800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x79400000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0x78600800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = 0x78400C00;
      } else {
        instr = 0x78400400;
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x78400400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x78600800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldrsb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    uint64_t imm12 = offset;
    if (imm12 > 4095) return;
    uint32_t instr = 0x39C00000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = (arm64_is_64bit(dst.reg) ? 0x38800C00 : 0x38C00C00);
      } else {
        instr = (arm64_is_64bit(dst.reg) ? 0x38800400 : 0x38C00400);
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    uint64_t imm12 = offset;
    if (imm12 > 4095) return;
    uint32_t instr = 0x38C00400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38E00860;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38A00800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldrsh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0x78A00800 : 0x78E00800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x79C00000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0x78A00800 : 0x78E00800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = (arm64_is_64bit(dst.reg) ? 0x78800C00 : 0x78C00C00);
      } else {
        instr = (arm64_is_64bit(dst.reg) ? 0x78800400 : 0x78C00400);
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x78C00400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x78E00800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldrsw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0xB8A00800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = 0xB9800000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0xB8A00800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = 0xB8800C00;
      } else {
        instr = 0xB8800400;
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = 0xB8800400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xB8A00800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldset(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8203000 : 0xB8203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldseta(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A03000 : 0xB8A03000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E03000 : 0xB8E03000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8603000 : 0xB8603000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldseth(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsetlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78203000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmax(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8204000 : 0xB8204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxa(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A04000 : 0xB8A04000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E04000 : 0xB8E04000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8604000 : 0xB8604000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmaxlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78204000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmin(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8205000 : 0xB8205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsmina(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A05000 : 0xB8A05000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E05000 : 0xB8E05000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8605000 : 0xB8605000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldsminlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78205000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8400800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38400800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78400800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtrsb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38C00800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtrsh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78C00800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldtrsw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8800800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumax(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8206000 : 0xB8206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxa(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A06000 : 0xB8A06000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E06000 : 0xB8E06000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8606000 : 0xB8606000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumaxlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78206000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumin(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8207000 : 0xB8207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldumina(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A07000 : 0xB8A07000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E07000 : 0xB8E07000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8607000 : 0xB8607000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminlb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lduminlh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78207000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldur(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldurb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldurh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78400000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldursb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38C00000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldursh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78C00000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldursw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8800000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldxp(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88600000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldxr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(dst.reg);
    
    uint32_t instr = is64 ? 0xC8400000 : 0x88400000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldxrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08400000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ldxrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48400000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lsl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lslr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04178000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lslv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lsr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02400;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x53007C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lsrr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04158000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_lsrv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02400;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mad(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x0400C000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_madd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1B000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E209400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_mls(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E209400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_mneg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1B00FC00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mov(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EA01C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x2A0003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xAA0003E0 : 0x2A0003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x11000000;
    instr = arm64_is_64bit(dst.reg) ? 0x91000000 : 0x11000000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    uint32_t instr = 0x320003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    uint32_t hw = (uint32_t)((raw_imm >> 0) & ((1u << 2) - 1u));
    uint32_t instr = 0x12800000;
    instr = arm64_is_64bit(dst.reg) ? 0x92800000 : 0x12800000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 2) - 1u) << 21);
    instr |= ((uint32_t)(hw & ((1u << 2) - 1u))) << 21;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_movi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_movk(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 16) - 1u);
    uint32_t hw = (uint32_t)((raw_imm >> 16) & ((1u << 2) - 1u));
    uint32_t instr = 0x72800000;
    instr = arm64_is_64bit(dst.reg) ? 0xF2800000 : 0x72800000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 16) - 1u) << 5);
    instr |= ((uint32_t)(imm & ((1u << 16) - 1u))) << 5;
    instr &= ~(((1u << 2) - 1u) << 21);
    instr |= ((uint32_t)(hw & ((1u << 2) - 1u))) << 21;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_movn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 16) - 1u);
    uint32_t hw = (uint32_t)((raw_imm >> 16) & ((1u << 2) - 1u));
    uint32_t instr = 0x12800000;
    instr = arm64_is_64bit(dst.reg) ? 0x92800000 : 0x12800000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 16) - 1u) << 5);
    instr |= ((uint32_t)(imm & ((1u << 16) - 1u))) << 5;
    instr &= ~(((1u << 2) - 1u) << 21);
    instr |= ((uint32_t)(hw & ((1u << 2) - 1u))) << 21;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_movprfx(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04102000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_movs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_movz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    imm &= ((1u << 16) - 1u);
    uint32_t hw = (uint32_t)((raw_imm >> 16) & ((1u << 2) - 1u));
    uint32_t instr = 0x52800000;
    instr = arm64_is_64bit(dst.reg) ? 0xD2800000 : 0x52800000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 16) - 1u) << 5);
    instr |= ((uint32_t)(imm & ((1u << 16) - 1u))) << 5;
    instr &= ~(((1u << 2) - 1u) << 21);
    instr |= ((uint32_t)(hw & ((1u << 2) - 1u))) << 21;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mrs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_msb(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x0400E000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_msr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_msub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1B008000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mul(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E209C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1B007C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mvn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E205800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x2A2003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xAA2003E0 : 0x2A2003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_mvni(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_nand(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_nands(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_neg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E20B800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x4B0003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xCB0003E0 : 0x4B0003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_negs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x6B0003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xEB0003E0 : 0x6B0003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ngc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5A0003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xDA0003E0 : 0x5A0003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ngcs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7A0003E0;
    instr = arm64_is_64bit(dst.reg) ? 0xFA0003E0 : 0x7A0003E0;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_nop(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503201F);
}

static inline void cj_nor(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_nors(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_not(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E205800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_nots(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_orn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EE01C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x2A200000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_orns(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_orr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0EA01C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x2A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x32000000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_orrs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_orv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_pacda(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10800;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacdza(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10800;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacdb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacdzb(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10C00;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacga(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9AC03000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacia(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_paciza(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10000;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacia1716(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503211F);
}

static inline void cj_paciasp(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503211F);
}

static inline void cj_paciaz(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503211F);
}

static inline void cj_pacib(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10400;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacizb(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC10400;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pacib1716(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503215F);
}

static inline void cj_pacibsp(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503215F);
}

static inline void cj_pacibz(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503215F);
}

static inline void cj_pfalse(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_pfirst(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_pmul(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E209C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_pnext(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfum(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_prfw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_psb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503223F);
}

static inline void cj_pssbb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503349F);
}

static inline void cj_ptest(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ptrue(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ptrues(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_punpkhi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_punpklo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_rax1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE608C00;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rbit(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E605800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5AC00000;
    instr = arm64_is_64bit(dst.reg) ? 0xDAC00000 : 0x5AC00000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rdffr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_rdffrs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_rdvl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ret(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD65F03C0);
}

static inline void cj_retaa(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD65F0BFF);
}

static inline void cj_retab(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD65F0FFF);
}

static inline void cj_rev(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5AC00800;
    instr = arm64_is_64bit(dst.reg) ? 0x5AC00800 : 0x5AC00800;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    uint32_t opc = arm64_is_64bit(dst.reg) ? 3 : 2;
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((opc & ((1u << 2) - 1u)) << 10);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rev16(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E201800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5AC00400;
    instr = arm64_is_64bit(dst.reg) ? 0xDAC00400 : 0x5AC00400;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rev32(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E200800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC00800;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rev64(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E200800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC00C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_revb(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x05248000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_revh(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x05258000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_revw(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x05268000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rmif(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ror(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;

    uint32_t instr = 0x13800000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rorv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC02C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rshrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F008C00;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_rshrn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F008C00;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_saba(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E207C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sabd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E207400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_sadalp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E206800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_saddlp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E202800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_saddlv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_saddv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50330FF);
}

static inline void cj_sbc(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x5A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sbcs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x7A000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sbfiz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sbfm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x13000000;
    instr = arm64_is_64bit(dst.reg) ? 0x13000000 : 0x13000000;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sbfx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_scvtf(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x0E79D800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x5E79D800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 'x' || src.reg[0] == 'w')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E220000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    int sf = arm64_is_64bit(src.reg) ? 1 : 0;
    instr &= ~(1u << 31);
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sdiv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC00C00;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sdivr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04160000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sdot(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E009400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_sel(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_setf8(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3A00080D;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_setf16(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3A00480D;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_setffr(cj_ctx* ctx) {
  cj_add_u32(ctx, 0x252C9000);
}

static inline void cj_sev(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503209F);
}

static inline void cj_sevl(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50320BF);
}

static inline void cj_sha1c(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E000000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E280800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha1m(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E002000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha1p(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E001000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha1su0(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E003000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha1su1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E281800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha256h2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E005000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha256h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E004000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha256su0(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E282800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha256su1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x5E006000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha512h2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE608400;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha512h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE608000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha512su0(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCEC08000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sha512su1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE608800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shadd(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E200400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_shll(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2E213800;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shll2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2E213800;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F008400;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shrn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F008400;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_shsub(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E202400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sli(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sm3partw1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE60C000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3partw2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE60C400;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3ss1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE400000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3tt1a(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE408000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3tt1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE408400;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3tt2a(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE408800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm3tt2b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE408C00;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm4e(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCEC08400;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sm4ekey(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE60C800;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smaddl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9B200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E206400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_smaxp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E20A400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smaxv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_smc(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_smin(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E206C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_sminp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E20AC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sminv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_smlal(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_smlsl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_smmla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x4E80A400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_smnegl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9B20FC00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smov(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_smsubl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9B208000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smulh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9B400000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_smull(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9B207C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_splice(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x052C8000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqabs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E207800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E200C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_sqdecb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdecd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdech(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdecp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdecw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdmlal(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdmlsl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqdmulh(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E20B400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqdmull(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqincb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqincd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqinch(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqincp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqincw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqneg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E207800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqrdmlah(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E008400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqrdmlsh(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E008C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqrdmulh(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E20B400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqrshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E205C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqrshrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqrshrun(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E204C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqshlu(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqshrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqshrun(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sqsub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E202C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_sqxtn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E214800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sqxtun(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E212800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_srhadd(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E201400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sri(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_srshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E205400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_srshr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_srsra(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ssbb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503309F);
}

static inline void cj_sshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x0E204400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sshll(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F00A400;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sshll2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F00A400;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sshr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ssra(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C007000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 2, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C00A000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C00A000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 3, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C006000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C006000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 4, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C002000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C002000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C802000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C802000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C802000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C802000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_st1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 2, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C008000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C008000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C808000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_st2b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st2d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st2g(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xD9A00400;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_st2h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st2w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st3(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 3, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C004000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C004000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C804000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_st3b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st3d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st3h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st3w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st4(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {
    arm64_vec_list_info list;
    if (!arm64_parse_vec_list_operand(dst, 4, &list)) return;
    arm64_vec_reg_info first = list.regs[0];
    int base_reg = arm64_parse_reg(src.reg);
    if (base_reg < 0) return;
    uint32_t instr = 0x0C000000;
    instr &= ~(0x1f << 5);
    instr |= ((base_reg & 0x1f) << 5);
    instr &= ~(((1u << 2) - 1u) << 10);
    instr |= ((uint32_t)(first.size & ((1u << 2) - 1u))) << 10;
    instr &= ~(((1u << 1) - 1u) << 30);
    instr |= ((uint32_t)(first.q & ((1u << 1) - 1u))) << 30;
    instr &= ~(((1u << 5) - 1u) << 0);
    instr |= ((uint32_t)(list.regs[0].reg & ((1u << 5) - 1u))) << 0;
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x0C000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x0C800000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_st4b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st4d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st4h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_st4w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_stadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_staddl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_staddb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_staddlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_staddh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_staddlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860001F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclrl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclrlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stclrlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860101F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steor(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steorl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steorb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steorlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steorh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_steorlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860201F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xD9200400;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stgm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD9A00000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stgp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x68800000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stllr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88800000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stllrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08800000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stllrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48800000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88808000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08808000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48808000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlur(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x99000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlurb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x19000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlurh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x59000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlxp(cj_ctx* ctx, cj_operand status, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (status.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88208000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rt2 & 0x1f) << 10);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlxr(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88008000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlxrb(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08008000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stlxrh(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48008000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stnp(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {
  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg1 = arm64_parse_reg(rt1.reg);
    if (reg1 < 0) return;
    int reg2 = arm64_parse_reg(rt2.reg);
    if (reg2 < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    int32_t offset = mem.mem.disp;
    
    int is64 = arm64_is_64bit(rt1.reg);
    int scale = is64 ? 8 : 4;
    
    if ((offset % scale) != 0) return;
    int32_t imm7 = offset / scale;
    if (imm7 < -64 || imm7 > 63) return;
    
    uint32_t instr = is64 ? 0xA9000000 : 0x29000000;
    
    instr |= (reg1 & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg2 & 0x1f) << 10);
    instr |= ((imm7 & 0x7f) << 15);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stnt1b(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_stnt1d(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_stnt1h(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_stnt1w(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_stp(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {
  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg1 = arm64_parse_reg(rt1.reg);
    if (reg1 < 0) return;
    int reg2 = arm64_parse_reg(rt2.reg);
    if (reg2 < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    int32_t offset = mem.mem.disp;
    
    int is64 = arm64_is_64bit(rt1.reg);
    int scale = is64 ? 8 : 4;
    
    if ((offset % scale) != 0) return;
    int32_t imm7 = offset / scale;
    if (imm7 < -64 || imm7 > 63) return;
    
    uint32_t instr = is64 ? 0xA9000000 : 0x29000000;
    
    instr |= (reg1 & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg2 & 0x1f) << 10);
    instr |= ((imm7 & 0x7f) << 15);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_str(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int qt = arm64_parse_q_reg(dst.reg);
    if (qt >= 0 && src.mem.mode == CJ_MEM_MODE_OFFSET && !src.mem.index) {
      const char* base = src.mem.base ? src.mem.base : "sp";
      int rn = arm64_parse_reg(base);
      if (rn < 0) return;
      int64_t offset = src.mem.disp;
      if (offset % 16 != 0) return;
      uint64_t imm12 = offset / 16;
      if (imm12 > 4095) return;
      uint32_t instr = 0x3D800000;
      instr |= ((imm12 & 0xfff) << 10);
      instr |= ((rn & 0x1f) << 5);
      instr |= (qt & 0x1f);
      cj_add_u32(ctx, instr);
      return;
    }
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8200800 : 0xB8200800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF9000000 : 0xB9000000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int qt = arm64_parse_q_reg(dst.reg);
    if (qt >= 0 && src.mem.mode == CJ_MEM_MODE_OFFSET && !src.mem.index) {
      const char* base = src.mem.base ? src.mem.base : "sp";
      int rn = arm64_parse_reg(base);
      if (rn < 0) return;
      int64_t offset = src.mem.disp;
      if (offset % 16 != 0) return;
      uint64_t imm12 = offset / 16;
      if (imm12 > 4095) return;
      uint32_t instr = 0x3D800000;
      instr |= ((imm12 & 0xfff) << 10);
      instr |= ((rn & 0x1f) << 5);
      instr |= (qt & 0x1f);
      cj_add_u32(ctx, instr);
      return;
    }
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8200800 : 0xB8200800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = (arm64_is_64bit(dst.reg) ? 0xF8000C00 : 0xB8000C00);
      } else {
        instr = (arm64_is_64bit(dst.reg) ? 0xF8000400 : 0xB8000400);
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    int size = arm64_is_64bit(dst.reg) ? 8 : 4;
    if (offset % size != 0) return;
    uint64_t imm12 = offset / size;
    if (imm12 > 4095) return;
    uint32_t instr = arm64_is_64bit(dst.reg) ? 0xF8000400 : 0xB8000400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xB8200800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xF8200800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_strb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    uint64_t imm12 = offset;
    if (imm12 > 4095) return;
    uint32_t instr = 0x39000000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = 0x38000C00;
      } else {
        instr = 0x38000400;
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    uint64_t imm12 = offset;
    if (imm12 > 4095) return;
    uint32_t instr = 0x38000400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38200800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x38206800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_strh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0x78200800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x79000000;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (src.type == CJ_MEMORY) {
    int rt = arm64_parse_reg(dst.reg);
    if (rt < 0) return;
    const char* base = src.mem.base ? src.mem.base : "sp";
    int rn = arm64_parse_reg(base);
    if (rn < 0) return;
    
    if (src.mem.index) {
      int rm = arm64_parse_reg(src.mem.index);
      if (rm < 0) return;
      
      int shift = 0;
      if (src.mem.scale == 2) shift = 1;
      else if (src.mem.scale == 4) shift = 2;
      else if (src.mem.scale == 8) shift = 3;
      else if (src.mem.scale != 1) return;
      
      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;
      
      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);
      if (S < 0) return;
      
      uint32_t instr = 0x78200800;
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr |= (S << 12);
      instr |= (0b011 << 13);
      instr |= ((rm & 0x1f) << 16);
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {
      int64_t offset = src.mem.disp;
      if (offset < -256 || offset > 255) return;
      uint32_t instr;
      if (src.mem.mode == CJ_MEM_MODE_PRE) {
        instr = 0x78000C00;
      } else {
        instr = 0x78000400;
      }
      instr |= (rt & 0x1f);
      instr |= ((rn & 0x1f) << 5);
      instr &= ~(((1u << 9) - 1u) << 12);
      instr |= ((uint32_t)(offset & ((1u << 9) - 1u))) << 12;
      cj_add_u32(ctx, instr);
      return;
    }
    
    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {
      int64_t offset = src.mem.disp;
    if (offset % 2 != 0) return;
    uint64_t imm12 = offset / 2;
    if (imm12 > 4095) return;
    uint32_t instr = 0x78000400;
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
      instr |= ((imm12 & 0xfff) << 10);
      cj_add_u32(ctx, instr);
      return;
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x78200800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stset(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsetl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsetb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsetlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stseth(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsetlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860301F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmaxl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmaxb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmaxlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmaxh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmaxlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860401F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsmin(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsminl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsminb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsminlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsminh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stsminlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860501F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sttr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8000800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sttrb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38000800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sttrh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78000800;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumaxl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumaxb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumaxlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumaxh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumaxlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860601F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stumin(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stuminl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xB820701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stuminb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3820701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stuminlb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x3860701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stuminh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7820701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stuminlh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7860701F;
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rd & ((1u << 5) - 1u)) << 16);
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stur(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xB8000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sturb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x38000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sturh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0x78000000;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~((1u << 5) - 1u);
    instr |= (rn & ((1u << 5) - 1u));
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stxp(cj_ctx* ctx, cj_operand status, cj_operand val1, cj_operand val2, cj_operand mem) {
  if (status.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(val1.reg);
    if (rt < 0 || (rt & 1) != 0) return;
    int rt2 = arm64_parse_reg(val2.reg);
    if (rt2 != rt + 1) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88200000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rt2 & 0x1f) << 10);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stxr(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x88000000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stxrb(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x08000000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stxrh(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {
  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int rs = arm64_parse_reg(status.reg);
    if (rs < 0) return;
    int rt = arm64_parse_reg(value.reg);
    if (rt < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x48000000;
    
    instr |= (rt & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((rs & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stz2g(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xD9E00400;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stzg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    uint64_t imm = src.constant;
    imm &= ((1u << 9) - 1u);
    uint32_t instr = 0xD9600400;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_stzgm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0xD9200000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E208400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x4B000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 12) - 1u);
    if (imm > 4095) return;
    uint32_t instr = 0x51000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr |= ((imm & 0xfff) << 10);
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x4B200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_subg(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_subp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9AC00000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_subps(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;

    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0xBAC00000;
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_subr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04030000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_subs(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x6B000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        return;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t imm = src.constant;
    imm &= ((1u << 12) - 1u);
    if (imm > 4095) return;
    uint32_t instr = 0x71000000;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr |= ((imm & 0xfff) << 10);
    uint32_t sh = 0;
    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {
      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;
      if (src.shift.amount == 0) {
        sh = 0;
      } else if (src.shift.amount == 12) {
        sh = 1;
      } else {
        return;
      }
    }
    instr &= ~(((1u << 1) - 1u) << 22);
    instr |= ((sh & ((1u << 1) - 1u)) << 22);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x6B200000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {
      uint32_t option = 0;
      switch (src.extend.kind) {
        case CJ_EXTEND_KIND_UXTB: option = 0; break;
        case CJ_EXTEND_KIND_UXTH: option = 1; break;
        case CJ_EXTEND_KIND_UXTW: option = 2; break;
        case CJ_EXTEND_KIND_UXTX: option = 3; break;
        case CJ_EXTEND_KIND_SXTB: option = 4; break;
        case CJ_EXTEND_KIND_SXTH: option = 5; break;
        case CJ_EXTEND_KIND_SXTW: option = 6; break;
        case CJ_EXTEND_KIND_SXTX: option = 7; break;
        default: return;
      }
      instr &= ~(((1u << 3) - 1u) << 13);
      instr |= ((option & ((1u << 3) - 1u)) << 13);
    }
    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {
      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;
      uint32_t extend_amount = src.extend.amount;
      if (extend_amount > ((1u << 3) - 1u)) return;
      instr &= ~(((1u << 3) - 1u) << 10);
      instr |= ((extend_amount & ((1u << 3) - 1u)) << 10);
    }
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sudot(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sunpkhi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sunpklo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_suqadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0E203800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_svc(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_swp(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8208000 : 0xB8208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpa(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8A08000 : 0xB8A08000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpal(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8E08000 : 0xB8E08000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpl(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    
    int is64 = arm64_is_64bit(rs.reg);
    
    uint32_t instr = is64 ? 0xF8608000 : 0xB8608000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpab(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpalb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swplb(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x38208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpah(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swpalh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swph(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_swplh(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {
  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {
    int reg_s = arm64_parse_reg(rs.reg);
    if (reg_s < 0) return;
    int reg_t = arm64_parse_reg(rt.reg);
    if (reg_t < 0) return;
    int rn = arm64_parse_reg(mem.mem.base);
    if (rn < 0) return;
    

    
    uint32_t instr = 0x78208000;
    
    instr |= (reg_t & 0x1f);
    instr |= ((rn & 0x1f) << 5);
    instr |= ((reg_s & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sxtb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x13001C00;
    instr = arm64_is_64bit(dst.reg) ? 0x13001C00 : 0x13001C00;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sxth(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x13003C00;
    instr = arm64_is_64bit(dst.reg) ? 0x13003C00 : 0x13003C00;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sxtw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x93407C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sxtl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F00A400;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sxtl2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0F00A400;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_sys(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_sysl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tbl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tbnz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tbx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tbz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tlbi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_trn1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_trn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_tsb(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503225F);
}

static inline void cj_tst(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x6A00001F;
    instr = arm64_is_64bit(dst.reg) ? 0xEA00001F : 0x6A00001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rd & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rn & ((1u << 5) - 1u)) << 16);
    uint32_t shift_mode = 0;
    switch (src.shift.kind) {
      case CJ_SHIFT_KIND_NONE:
      case CJ_SHIFT_KIND_LSL:
        shift_mode = 0;
        break;
      case CJ_SHIFT_KIND_LSR:
        shift_mode = 1;
        break;
      case CJ_SHIFT_KIND_ASR:
        shift_mode = 2;
        break;
      case CJ_SHIFT_KIND_ROR:
        shift_mode = 3;
        break;
      default:
        return;
    }
    instr &= ~(((1u << 2) - 1u) << 22);
    instr |= ((shift_mode & ((1u << 2) - 1u)) << 22);
    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;
    if (arm64_is_64bit(dst.reg)) {
      if (shift_amount > 63u) return;
    } else {
      if (shift_amount > 31u) return;
    }
    instr &= ~(((1u << 6) - 1u) << 10);
    instr |= ((shift_amount & ((1u << 6) - 1u)) << 10);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    uint64_t raw_imm = src.constant;
    uint64_t imm = raw_imm;
    uint32_t instr = 0x7200001F;
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uaba(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E207C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uabd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E207400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_uadalp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E206800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uaddlp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E202800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uaddlv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uaddv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ubfiz(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ubfm(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x53000000;
    instr = arm64_is_64bit(dst.reg) ? 0x53000000 : 0x53000000;
    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ubfx(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ucvtf(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {
        uint32_t instr = 0x2E79D800;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vn.reg & 0x1f) << 5);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_fp_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x7E79D800;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 'x' || src.reg[0] == 'w')) {
    int rd = arm64_parse_fp_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x1E230000;
    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;
    instr &= ~(0x3 << 22);
    instr |= (ftype << 22);
    int sf = arm64_is_64bit(src.reg) ? 1 : 0;
    instr &= ~(1u << 31);
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_udf(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_udiv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x1AC00800;
    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;
    instr |= (sf << 31);
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_udivr(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x04170000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_udot(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E009400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_uhadd(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E200400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uhsub(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E202400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umaddl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9BA00000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umax(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E206400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_umaxp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E20A400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umaxv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_umin(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E206C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_uminp(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E20AC00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uminv(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_umlal(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_umlsl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ummla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x6E80A400;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_umnegl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9BA0FC00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umov(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_umsubl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9BA08000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umulh(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9BC00000;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_umull(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = rd;
    int rm = arm64_parse_reg(src.reg);
    if (rm < 0) return;
    uint32_t instr = 0x9BA07C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    instr &= ~(((1u << 5) - 1u) << 16);
    instr |= ((rm & ((1u << 5) - 1u)) << 16);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uqadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E200C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_uqdecb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqdecd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqdech(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqdecp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqdecw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqincb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqincd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqinch(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqincp(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqincw(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqrshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E205C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uqrshrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E204C00;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uqshrn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uqsub(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x2E202C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_uqxtn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E214800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_urecpe(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x0EA1C800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_urhadd(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E201400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_urshl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E205400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_urshr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_ursqrte(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2EA1C800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ursra(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_usdot(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x0E809C00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_ushl(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);
    if (vn.reg < 0) return;
    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);
    if (vm.reg < 0) return;
    
    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;
    
    uint32_t instr = 0x2E204400;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    instr |= ((vm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ushll(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2F00A400;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ushll2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2F00A400;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_ushr(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_usmmla(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg >= 0) {
      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);
      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {
        uint32_t instr = 0x4E80AC00;
        instr |= (vd.q << 30);
        instr |= ((vd.size & 0x3) << 22);
        instr |= (vd.reg & 0x1f);
        instr |= ((vd.reg & 0x1f) << 5);
        instr |= ((vm.reg & 0x1f) << 16);
        cj_add_u32(ctx, instr);
        return;
      }
    }
  }
}

static inline void cj_usqadd(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    if (vd.q != vn.q || vd.size != vn.size) return;
    
    uint32_t instr = 0x2E203800;
    instr |= (vd.q << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_usra(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uunpkhi(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uunpklo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uxtb(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x53001C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uxth(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount) {
    int rd = arm64_parse_reg(dst.reg);
    if (rd < 0) return;
    int rn = arm64_parse_reg(src.reg);
    if (rn < 0) return;
    uint32_t instr = 0x53003C00;
    instr &= ~((1u << 5) - 1u);
    instr |= (rd & ((1u << 5) - 1u));
    instr &= ~(((1u << 5) - 1u) << 5);
    instr |= ((rn & ((1u << 5) - 1u)) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uxtw(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {
  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {
    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);
    if (zd.reg < 0) return;
    int pg = arm64_parse_p_reg(pred.reg);
    if (pg < 0) return;
    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);
    if (zn.reg < 0) return;
    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);
    if (zm.reg < 0) return;
    
    if (zd.size != zn.size || zd.size != zm.size) return;
    
    uint32_t instr = 0x0415A000;
    instr |= ((zd.size & 0x3) << 22);
    instr |= ((pg & 0x7) << 10);
    instr |= (zd.reg & 0x1f);
    instr |= ((zn.reg & 0x1f) << 5);
    instr |= ((zm.reg & 0x1f) << 16);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uxtl(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2F00A400;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uxtl2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x2F00A400;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_uzp1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_uzp2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_wfe(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503205F);
}

static inline void cj_wfi(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503207F);
}

static inline void cj_whilele(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_whilelo(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_whilels(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_whilelt(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_wrffr(cj_ctx* ctx, cj_operand dst) {
  (void)dst;
}

static inline void cj_xaflag(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD500403F);
}

static inline void cj_xar(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0xCE800000;
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_xpacd(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC147E0;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_xpaci(cj_ctx* ctx, cj_operand dst) {
  if (dst.type == CJ_REGISTER) {
    int rn = arm64_parse_reg(dst.reg);
    if (rn < 0) return;
    uint32_t instr = 0xDAC143E0;
    instr |= ((rn & 0x1f) << 5);
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_xpaclri(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD50320FF);
}

static inline void cj_xtn(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E212800;
    instr &= ~(1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_xtn2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {
    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);
    if (vd.reg < 0) return;
    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);
    if (vn.reg < 0) return;
    
    uint32_t instr = 0x0E212800;
    instr |= (1u << 30);
    instr |= ((vd.size & 0x3) << 22);
    instr |= (vd.reg & 0x1f);
    instr |= ((vn.reg & 0x1f) << 5);
    
    cj_add_u32(ctx, instr);
    return;
  }
}

static inline void cj_yield(cj_ctx* ctx) {
  cj_add_u32(ctx, 0xD503203F);
}

static inline void cj_zip1(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_zip2(cj_ctx* ctx, cj_operand dst, cj_operand src) {
}

static inline void cj_b(cj_ctx* ctx, cj_label label) {
  cj_emit_branch(ctx, 0x14000000, label, 26, 0);
}

static inline void cj_bl(cj_ctx* ctx, cj_label label) {
  cj_emit_branch(ctx, 0x94000000, label, 26, 0);
}

static inline void cj_beq(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 0;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bne(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 1;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bcs(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 2;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bcc(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 3;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bmi(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 4;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bpl(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 5;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bvs(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 6;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bvc(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 7;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bhi(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 8;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bls(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 9;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bge(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 10;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_blt(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 11;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bgt(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 12;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_ble(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 13;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_bal(cj_ctx* ctx, cj_label label) {
  uint32_t base = 0x54000000 | 14;
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_cbz(cj_ctx* ctx, cj_operand reg, cj_label label) {
  if (reg.type != CJ_REGISTER) return;
  int rt = arm64_parse_reg(reg.reg);
  if (rt < 0) return;
  uint32_t base = 0x34000000 | (rt & 0x1f);
  if (arm64_is_64bit(reg.reg)) {
    base |= (1 << 31);
  }
  cj_emit_branch(ctx, base, label, 19, 5);
}

static inline void cj_cbnz(cj_ctx* ctx, cj_operand reg, cj_label label) {
  if (reg.type != CJ_REGISTER) return;
  int rt = arm64_parse_reg(reg.reg);
  if (rt < 0) return;
  uint32_t base = 0x34000000 | (1 << 24) | (rt & 0x1f);
  if (arm64_is_64bit(reg.reg)) {
    base |= (1 << 31);
  }
  cj_emit_branch(ctx, base, label, 19, 5);
}

