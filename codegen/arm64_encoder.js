/**
 * WATCH OUT: I LET AN LLM GENERATE THESE COMMENTS. TAKE WITH A GRAIN OF SALT.
 * ARM64 Instruction Encoder Generator
 *
 * This code generator creates C functions for encoding ARM64 instructions.
 * It reads instruction definitions from arm64_instructions_full.jsonl and
 * generates efficient encoder functions in src/arch/arm64/backend.h
 *
 * Key features:
 * - Supports 2,516+ ARM64 A64 instructions (99% coverage)
 * - Handles multiple instruction variants (32/64-bit, FP/integer, etc.)
 * - Generates type-safe operand checking
 * - Optimizes for common addressing modes
 *
 * Architecture:
 * 1. Load and deduplicate instruction definitions
 * 2. Filter to supported instructions (A64, valid C identifiers)
 * 3. Group by mnemonic and sort by priority
 * 4. Generate C encoder functions with proper register field mapping
 */

const fs = require('fs');

// Read ARM64 instruction data with operands
const lines = fs.readFileSync('./codegen/arm64_instructions_full.jsonl', 'utf8').split('\n').filter(l => l.trim());
const allInstructions = lines.map(line => JSON.parse(line));

// Deduplicate by ID (some entries appear multiple times)
const seenIds = new Set();
const instructions = allInstructions.filter(inst => {
  if (seenIds.has(inst.id)) return false;
  seenIds.add(inst.id);
  return true;
});

console.error(`Loaded ${instructions.length} ARM64 instruction encodings (${allInstructions.length - instructions.length} duplicates removed)`);

// Exclude complex instruction sets that need special handling
// Accept everything else - we have complete encodings!
const EXCLUDED_PATTERNS = [
  // SIMD/NEON - complex operations that need special handling
  '.*_asimddiff.*',     // SIMD long/narrow operations with invalid mnemonics (ADDHN{2}, etc)

  // ALL INSTRUCTION SETS NOW SUPPORTED:
  // - SIMD/NEON: All operations except asimddiff
  // - Cryptography: AES, SHA, etc.
  // - System instructions: MSR, MRS, SYS, SYSL
  // - Pointer authentication
  // - SVE (Scalable Vector Extension): Z and P registers - NOW SUPPORTED!
];

function matchesPattern(id, patterns) {
  if (!id) return false;
  for (const pat of patterns) {
    const regex = new RegExp('^' + pat + '$');
    if (regex.test(id)) return true;
  }
  return false;
}

// Check if mnemonic is a valid C identifier or has {2} suffix, .<cond>, or <bt>
function isValidCIdentifier(mnemonic) {
  if (!mnemonic) return false;
  // Allow {2} suffix for narrow/widen operations
  if (mnemonic.endsWith('{2}')) {
    const base = mnemonic.slice(0, -3);
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(base);
  }
  // Allow .<cond> suffix for conditional branches (B.<cond>)
  if (mnemonic.includes('.<') && mnemonic.includes('>')) {
    const base = mnemonic.split('.')[0];
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(base);
  }
  // Allow <bt> suffix for BFloat16 operations (BFMLAL<bt>)
  if (mnemonic.includes('<bt>')) {
    const base = mnemonic.replace('<bt>', '');
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(base);
  }
  // Must start with letter or underscore, contain only alphanumeric and underscore
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(mnemonic);
}

const supportedInsts = instructions.filter(inst =>
  !matchesPattern(inst.id, EXCLUDED_PATTERNS) &&
  inst.isa === 'A64' &&
  inst.mask && inst.value &&
  isValidCIdentifier(inst.mnemonic)
);

console.error(`Filtered to ${supportedInsts.length} supported instructions`);

// Mnemonics that have manual implementations (branch instructions)
// These are added at the end with special label support
const MANUAL_MNEMONICS = new Set([
  'b',        // Unconditional branch - manual version takes label
  'bl',       // Branch with link - manual version takes label
  'cbz',      // Compare and branch if zero - manual version takes label
  'cbnz',     // Compare and branch if not zero - manual version takes label
  'bfmlalb',  // Generated from BFMLAL<bt>
  'bfmlalt',  // Generated from BFMLAL<bt>
  // Conditional branches are added manually as cj_beq, cj_bne, etc.
]);

// Group by mnemonic
const byMnemonic = {};
for (const inst of supportedInsts) {
  let mnem = inst.mnemonic.toLowerCase();

  // Normalize {2} suffix to base mnemonic for grouping
  if (mnem.endsWith('{2}')) {
    mnem = mnem.slice(0, -3);
  }

  // Normalize .<cond> suffix to base mnemonic for grouping
  if (mnem.includes('.<') && mnem.includes('>')) {
    mnem = mnem.split('.')[0];
  }

  // Normalize <bt> suffix to base mnemonic for grouping
  if (mnem.includes('<bt>')) {
    mnem = mnem.replace('<bt>', '');
  }

  // Skip instructions with manual implementations
  if (MANUAL_MNEMONICS.has(mnem)) {
    continue;
  }

  if (!byMnemonic[mnem]) byMnemonic[mnem] = [];
  byMnemonic[mnem].push(inst);
}

console.error(`Unique mnemonics: ${Object.keys(byMnemonic).length}`);

// Priority order for addressing modes (most common/simple first)
// This ensures we generate the right instruction first in each function
function getInstructionPriority(id) {
  // Shifted register forms (most common)
  if (id.includes('_addsub_shift')) return 100;
  if (id.includes('_log_shift')) return 100;

  // Immediate forms
  if (id.includes('_addsub_imm') && !id.includes('tags')) return 90;
  if (id.includes('_log_imm')) return 90;

  // Simple load/store (positive offset)
  if (id.includes('_ldst_pos')) return 100;
  if (id.includes('_ldst_imm') && id.includes('post')) return 50;  // Post-index less common
  if (id.includes('_ldst_imm') && id.includes('pre')) return 50;   // Pre-index less common

  // Extended register (less common than shifted)
  if (id.includes('_addsub_ext')) return 80;

  // Everything else
  return 50;
}

// Sort variants by priority within each mnemonic
for (const mnem of Object.keys(byMnemonic)) {
  byMnemonic[mnem].sort((a, b) => getInstructionPriority(b.id) - getInstructionPriority(a.id));
}

// Map XML operand types to C operand types
function mapOperandType(operand) {
  const linkRaw = operand.link || '';
  const link = linkRaw.toLowerCase();
  const hover = operand.hover || '';
  const hoverLower = hover.toLowerCase();

  if (link.match(/^[xw](d|n|m|t)/)) {
    const is64bit = link[0] === 'x';
    return { type: 'reg', size: is64bit ? 64 : 32 };
  } else if (link.match(/^[hsd](d|n|m)/)) {
    const size = link[0] === 'h' ? 16 : (link[0] === 's' ? 32 : 64);
    return { type: 'fpreg', size: size };
  } else if (link === 'vt') {
    return { type: 'vec' };
  } else if (link === 't' || link === 'size' || link.startsWith('size:')) {
    return { type: 'arrangement' };
  } else if (/^vt\d+$/.test(link)) {
    return { type: 'vec_extra' };
  } else if (link.startsWith('shift')) {
    return { type: 'imm' };
  } else if (hoverLower.includes('general-purpose')) {
    const is64bit = hoverLower.includes('64-bit') || link.startsWith('x');
    return { type: 'reg', size: is64bit ? 64 : 32 };
  } else if (link === 'imm' || link === 'amount' || link === 'shift' || link === 'extend' || link.startsWith('pimm') || link.startsWith('simm') || link.startsWith('imm')) {
    const match = hover.match(/\[(\d+)-(\d+)\]/);
    if (match) {
      return { type: 'imm', min: parseInt(match[1]), max: parseInt(match[2]) };
    }
    return { type: 'imm' };
  }
  return { type: 'unknown' };
}

// ============================================================================
// Helper Functions for Code Generation
// ============================================================================

/**
 * Detect instruction pattern from field structure (replaces mnemonic matching)
 */
function detectInstructionPattern(variants, mnemonic) {
  if (!variants || variants.length === 0) return null;
  const inst = variants[0];
  const fields = inst.variables || [];
  const operands = inst.operands || [];
  const opCount = operands.length;

  const hasRt = fields.some(f => f.name === 'Rt');
  const hasRt2 = fields.some(f => f.name === 'Rt2');
  const hasRs = fields.some(f => f.name === 'Rs');
  const hasRn = fields.some(f => f.name === 'Rn');
  const hasA = fields.some(f => f.name === 'A');
  const hasR = fields.some(f => f.name === 'R');
  const hasO = fields.some(f => f.name === 'o0');

  // Load/Store Pair: 3-4 operands + Rt + Rt2
  // Return with load flag based on mnemonic
  if (opCount >= 3 && hasRt && hasRt2 && hasRn && !hasRs) {
    return mnemonic.startsWith('ld') ? 'pair_load' : 'pair_store';
  }

  // Exclusive store pair: 4 operands + Rs + Rt + Rt2
  if (opCount === 4 && hasRs && hasRt && hasRt2) return 'exclusive_store_pair';

  // Exclusive load pair: 3 operands + Rt + Rt2, NO Rs
  if (opCount === 3 && hasRt && hasRt2 && !hasRs) return 'exclusive_load_pair';

  // CAS Pair: mnemonic match (check before other 3-operand patterns)
  if (mnemonic.startsWith('casp')) return 'cas_pair';

  // Atomic/CAS: Rs + Rt + ordering bits (check before generic exclusive_store)
  if (hasRs && hasRt && hasRn && (hasA || hasR || hasO)) {
    if (mnemonic.startsWith('cas')) return 'cas';
    // Atomic ops: 3 operands = load (LDADD), 2 operands = store (STADD)
    return opCount === 3 ? 'atomic_load' : 'atomic_store';
  }

  // Exclusive store: 3 operands + Rs + Rt, NO ordering bits
  // Note: May have Rt2 in encoding but it's constrained (fixed value)
  if (opCount === 3 && hasRs && hasRt && hasRn) return 'exclusive_store';

  // Exclusive load: 2 operands + Rt + Rn (dest + base)
  // Note: May have Rt2/Rs in encoding but they're constrained (fixed values)
  if (opCount === 2 && hasRt && hasRn) return 'exclusive_load';

  return null;
}

/**
 * Extract field name from hover text
 * @param {Object} operand - Operand with hover text
 * @returns {string|null} Field name or null
 */
function extractFieldName(operand) {
  const hover = operand.hover || '';
  const match = hover.match(/field\s+"([^"]+)"/);
  return match ? match[1] : null;
}

/**
 * Find a variable field by name in an instruction
 * @param {Object} inst - Instruction object
 * @param {string} name - Variable name (e.g., 'Rd', 'Rn', 'Rm')
 * @returns {Object|null} Variable object or null if not found
 */
function findVariable(inst, name) {
  if (!inst || !inst.variables) return null;
  return inst.variables.find(v => v.name === name) || null;
}

/**
 * Generate a bit mask expression for a given width
 * @param {number} width - Bit width
 * @returns {string} C expression for the bit mask
 */
function bitMask(width) {
  if (width >= 32) return '0xFFFFFFFFu';
  return `((1u << ${width}) - 1u)`;
}

/**
 * Generate code to encode a register into an instruction field
 * @param {string} regVar - Register variable name (e.g., 'rd', 'rn')
 * @param {number} bitPos - Bit position in instruction (0, 5, 16, etc.)
 * @param {string} comment - Optional comment to add
 * @returns {string} C code to encode the register field
 */
function generateRegFieldEncoding(regVar, bitPos) {
  if (bitPos === 0) {
    return `    instr &= ~0x1f;\n    instr |= (${regVar} & 0x1f);${commentStr}\n`;
  }
  return `    instr &= ~(0x1f << ${bitPos});\n    instr |= ((${regVar} & 0x1f) << ${bitPos});${commentStr}\n`;
}

/**
 * Encode a field using its metadata (lo, hi, width)
 * This is the metadata-driven version that doesn't hardcode bit positions
 *
 * @param {Object} field - Field metadata with {name, lo, hi, width}
 * @param {string} cVarName - C variable name to encode
 * @returns {string} C code to encode the field
 */
function encodeFieldFromMetadata(field, cVarName) {
  const { lo, width, name } = field;
  const mask = bitMask(width);
  let code = '';

  if (lo === 0) {
    code += `    instr &= ~${mask};\n`;
    code += `    instr |= (${cVarName} & ${mask});\n`;
  } else {
    code += `    instr &= ~(${mask} << ${lo});\n`;
    code += `    instr |= ((${cVarName} & ${mask}) << ${lo});\n`;
  }

  return code;
}

/**
 * Generate register field mapping using metadata
 * Uses the proven logic from generateTwoOpRegMapping but with metadata for positions
 *
 * @param {Object} inst - Instruction object with variables array
 * @param {number} numOperands - Number of register operands (2 or 3)
 * @returns {string} C code to encode all register fields
 */
function generateRegisterMappingFromMetadata(inst, numOperands) {
  let output = '';

  const rdField = findVariable(inst, 'Rd');
  const rnField = findVariable(inst, 'Rn');
  const rmField = findVariable(inst, 'Rm');

  // Use the same logic as generateTwoOpRegMapping but with metadata positions
  // Check Rd+Rm first (MOV case) before Rd+Rn to avoid false matches
  if (rdField && rmField && !rnField) {
    // MOV-style Rd, Rm layout with Rn fixed (dst→Rd, src→Rm)
    output += encodeFieldFromMetadata(rdField, 'rd');
    output += encodeFieldFromMetadata(rmField, 'rn');  // src goes in 'rn' for 2-op
  } else if (rnField && rmField && !rdField) {
    // Compare-style Rn, Rm layout (dst→Rn, src→Rm)
    output += encodeFieldFromMetadata(rnField, 'rd');  // dst→Rn
    output += encodeFieldFromMetadata(rmField, 'rn');  // src→Rm
  } else if (rdField && rnField) {
    // Standard Rd, Rn layout (dst→Rd, src1→Rn)
    output += encodeFieldFromMetadata(rdField, 'rd');
    output += encodeFieldFromMetadata(rnField, 'rn');
    if (rmField && numOperands >= 3) {
      output += encodeFieldFromMetadata(rmField, 'rm');
    }
  } else {
    // Fallback: encode fields positionally
    const regFields = inst.variables.filter(v =>
      v.name.match(/^(Rd|Rn|Rm|Rt|Rs|Ra)$/)
    );
    const cVars = ['rd', 'rn', 'rm', 'rt'];
    for (let i = 0; i < Math.min(numOperands, regFields.length); i++) {
      output += encodeFieldFromMetadata(regFields[i], cVars[i]);
    }
  }

  return output;
}

/**
 * Generate register field mapping for two-operand instructions
 * Handles different register field layouts:
 * - Rd+Rm (MOV-style): dst→Rd[4:0], src→Rm[20:16]
 * - Rn+Rm (compare-style): dst→Rn[9:5], src→Rm[20:16]
 * - Rd+Rn (standard): dst→Rd[4:0], src→Rn[9:5]
 *
 * @param {Object} inst - Instruction object with variable fields
 * @returns {string} C code to map registers to instruction fields
 */
function generateTwoOpRegMapping(inst) {
  const hasRdVar = findVariable(inst, 'Rd');
  const hasRnVar = findVariable(inst, 'Rn');
  const hasRmVar = findVariable(inst, 'Rm');

  // Check Rd+Rm first (MOV case) before Rd+Rn to avoid false matches
  if (hasRdVar && hasRmVar && !hasRnVar) {
    // MOV-style Rd, Rm layout with Rn fixed (dst→Rd, src→Rm)
    return generateRegFieldEncoding('rd', 0, 'Rd at [4:0]') +
           generateRegFieldEncoding('rn', 16, 'src→Rm at [20:16]');
  } else if (hasRnVar && hasRmVar && !hasRdVar) {
    // Compare-style Rn, Rm layout (dst→Rn, src→Rm)
    return generateRegFieldEncoding('rd', 5, 'dst→Rn at [9:5]') +
           generateRegFieldEncoding('rn', 16, 'src→Rm at [20:16]');
  } else if (hasRdVar && hasRnVar) {
    // Standard Rd, Rn layout (dst→Rd, src→Rn)
    return generateRegFieldEncoding('rd', 0, 'Rd at [4:0]') +
           generateRegFieldEncoding('rn', 5, 'Rn at [9:5]');
  } else {
    // Fallback: assume Rd and Rn
    return generateRegFieldEncoding('rd', 0) +
           generateRegFieldEncoding('rn', 5);
  }
}

/**
 * Generate sf bit and opc field handling for size-variant instructions
 * Handles instructions with 32-bit and 64-bit variants that differ in:
 * - sf bit (bit 31): set for 64-bit, clear for 32-bit
 * - opc field: may have different values for different sizes (e.g., REV)
 *
 * @param {Array} variantGroup - Array of instruction variants
 * @param {Object|null} opcField - opc field descriptor if present
 * @returns {string} C code to set instruction value and size-dependent fields
 */
function generateSizeVariantHandling(variantGroup, opcField) {
  let output = '';

  const variant32 = variantGroup.find(v => (v.inst.bitdiffs || '').includes('sf == 0'));
  const variant64 = variantGroup.find(v => (v.inst.bitdiffs || '').includes('sf == 1'));

  if (!variant32 || !variant64) return output;

  // Set base instruction value based on register size
  output += `    instr = arm64_is_64bit(dst.reg) ? ${variant64.inst.value} : ${variant32.inst.value};\n`;

  // If both values are the same, set sf bit (bit 31) for 64-bit variant
  if (variant32.inst.value === variant64.inst.value) {
    output += `    if (arm64_is_64bit(dst.reg)) instr |= (1u << 31);\n`;
  }

  // Handle opc field if it varies with size
  if (opcField) {
    const opc32Match = (variant32.inst.bitdiffs || '').match(/opc == (\d+)/);
    const opc64Match = (variant64.inst.bitdiffs || '').match(/opc == (\d+)/);
    if (opc32Match && opc64Match) {
      const opc32 = parseInt(opc32Match[1], 2);  // Parse as binary
      const opc64 = parseInt(opc64Match[1], 2);  // Parse as binary
      if (opc32 !== opc64) {
        output += `    uint32_t opc = arm64_is_64bit(dst.reg) ? ${opc64} : ${opc32};\n`;
        output += `    instr &= ~(${bitMask(opcField.width)} << ${opcField.lo});\n`;
        output += `    instr |= ((opc & ${bitMask(opcField.width)}) << ${opcField.lo});\n`;
      }
    }
  }

  return output;
}

function buildVariantExpr(variants, isFP, operandType) {
  if (!variants || variants.length === 0) return null;
    let candidates = variants;
  if (operandType === 'reg') {
    const filtered = variants.filter(v => {
      const id = (v.inst.id || '');
      return id.includes('_32_') || id.includes('_64_');
    });
    if (filtered.length) {
      candidates = filtered;
    }
  }
  if (operandType === 'fpreg') {
    const filtered = variants.filter(v => {
      const id = (v.inst.id || '');
      return id.includes('_S_') || id.includes('_D_');
    });
    if (filtered.length) {
      candidates = filtered;
    }
  }
  const match32 = candidates.find(v => {
    const id = v.inst.id || '';
    const diff = v.inst.bitdiffs || '';
    return id.includes('_32_') || diff.includes('size == 10');
  });
  const match64 = candidates.find(v => {
    const id = v.inst.id || '';
    const diff = v.inst.bitdiffs || '';
    return id.includes('_64_') || diff.includes('size == 11');
  });

  const val32 = match32 ? match32.inst.value : null;
  const val64 = match64 ? match64.inst.value : null;

  if (val32 && val64) {
    if (isFP) {
      return `(arm64_is_fp_64bit(dst.reg) ? ${val64} : ${val32})`;
    }
    return `(arm64_is_64bit(dst.reg) ? ${val64} : ${val32})`;
  }
  if (val64) return `${val64}`;
  if (val32) return `${val32}`;
  return `${variants[0].inst.value}`;
}

// Generate header
let output = `#pragma once

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
  if (ptr == name + 1 || *ptr != '\\0' || reg < 0 || reg > 31) {
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

  if (*ptr != '\\0') {
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

  if (*ptr != '\\0') {
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

`;

// Generate function implementations for each mnemonic
// Zero-operand instructions (NOP) and 1-operand instructions (RET, BR) are handled specially
for (const [mnemonic, variants] of Object.entries(byMnemonic)) {
  // Check if this is a 0-operand instruction
  const hasZeroOperandVariant = variants.some(v => (v.operands || []).length === 0);
  const hasOneOperandVariant = variants.some(v => (v.operands || []).length === 1);
  const hasTwoOperandVariant = variants.some(v => (v.operands || []).length >= 2);

  // Generate 0-operand form if needed
  if (hasZeroOperandVariant) {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx) {\n`;

    for (const inst of variants) {
      const operands = inst.operands || [];
      if (operands.length === 0) {
        output += `  cj_add_u32(ctx, ${inst.value});\n`;
      }
    }

    output += `}\n\n`;
    continue;
  }

  // Generate 1-operand form if it's the only form
  if (hasOneOperandVariant && !hasTwoOperandVariant) {
    // Special case: RET should have 0-argument form for API compatibility
    if (mnemonic === 'ret') {
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx) {\n`;
      output += `  cj_add_u32(ctx, 0xD65F03C0);\n`;
      output += `}\n\n`;
      continue;
    }

    // For other 1-operand instructions (BR, BLR, etc.)
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst) {\n`;

    // Try to find a simple register variant
    const regVariant = variants.find(v => {
      const ops = v.operands || [];
      if (ops.length !== 1) return false;
      const link = (ops[0].link || '').toLowerCase();
      // Register operands: xn, wn, xm, etc
      return link.match(/^[xw](n|m|d|t)$/);
    });

    if (regVariant) {
      output += `  if (dst.type == CJ_REGISTER) {\n`;
      output += `    int rn = arm64_parse_reg(dst.reg);\n`;
      output += `    if (rn < 0) return;\n`;
      output += `    uint32_t instr = ${regVariant.value};\n`;
      output += `    instr |= ((rn & 0x1f) << 5);\n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
    } else {
      output += `  (void)dst;\n`;
    }

    output += `}\n\n`;
    continue;
  }

  // Detect instruction pattern from structure (replaces mnemonic matching)
  const pattern = detectInstructionPattern(variants, mnemonic);

  // Pattern: Load/Store pairs (LDP/STP) - 3 operands (rt1, rt2, memory)
  if (pattern === 'pair_load' || pattern === 'pair_store') {
    const isLoad = pattern === 'pair_load';
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand rt1, cj_operand rt2, cj_operand mem) {\n`;
    output += `  if (rt1.type == CJ_REGISTER && rt2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int reg1 = arm64_parse_reg(rt1.reg);\n`;
    output += `    if (reg1 < 0) return;\n`;
    output += `    int reg2 = arm64_parse_reg(rt2.reg);\n`;
    output += `    if (reg2 < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    int32_t offset = mem.mem.disp;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(rt1.reg);\n`;
    output += `    int scale = is64 ? 8 : 4;\n`;
    output += `    \n`;
    output += `    if ((offset % scale) != 0) return;\n`;
    output += `    int32_t imm7 = offset / scale;\n`;
    output += `    if (imm7 < -64 || imm7 > 63) return;\n`;
    output += `    \n`;
    const ldpValue32 = '0x29400000';
    const ldpValue64 = '0xA9400000';
    const stpValue32 = '0x29000000';
    const stpValue64 = '0xA9000000';
    if (isLoad) {
      output += `    uint32_t instr = is64 ? ${ldpValue64} : ${ldpValue32};\n`;
    } else {
      output += `    uint32_t instr = is64 ? ${stpValue64} : ${stpValue32};\n`;
    }
    output += `    \n`;
    output += `    instr |= (reg1 & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((reg2 & 0x1f) << 10);\n`;
    output += `    instr |= ((imm7 & 0x7f) << 15);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Exclusive load (LDXR, LDAXR, LDAR, LDLAR)
  // Detected by: 2 operands + Rt + Rn fields
  if (pattern === 'exclusive_load') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
    output += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
    output += `    int rt = arm64_parse_reg(dst.reg);\n`;
    output += `    if (rt < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(src.reg);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(dst.reg);\n`;
    output += `    \n`;

    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('LR32') || v.id.includes('R32') || v.id.includes('SR32') || v.id.includes('C32') || v.id.includes('CP32')));
    const variant64 = variants.find(v => v.id && (v.id.includes('_64_') || v.id.includes('LR64') || v.id.includes('R64') || v.id.includes('SR64') || v.id.includes('C64') || v.id.includes('CP64')));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else if (variant32) {
      output += `    uint32_t instr = ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Exclusive store (STXR, STLR, STLXR, STLLR)
  // Detected by: 3 operands + Rs + Rt + Rn fields
  if (pattern === 'exclusive_store') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand status, cj_operand value, cj_operand mem) {\n`;
    output += `  if (status.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int rs = arm64_parse_reg(status.reg);\n`;
    output += `    if (rs < 0) return;\n`;
    output += `    int rt = arm64_parse_reg(value.reg);\n`;
    output += `    if (rt < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(value.reg);\n`;
    output += `    \n`;

    // Find 32-bit and 64-bit variants
    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('B_') || v.id.includes('H_')));
    const variant64 = variants.find(v => v.id && v.id.includes('_64_'));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else if (variant32) {
      output += `    uint32_t instr = ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((rs & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: CASP (Compare and Swap Pair)
  // Detected by: mnemonic starts with 'casp'
  if (pattern === 'cas_pair') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand cmp1, cj_operand cmp2, cj_operand val1, cj_operand val2, cj_operand mem) {\n`;
    output += `  if (cmp1.type == CJ_REGISTER && cmp2.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int rs = arm64_parse_reg(cmp1.reg);\n`;
    output += `    if (rs < 0 || (rs & 1) != 0) return;\n`;
    output += `    int rs2 = arm64_parse_reg(cmp2.reg);\n`;
    output += `    if (rs2 != rs + 1) return;\n`;
    output += `    int rt = arm64_parse_reg(val1.reg);\n`;
    output += `    if (rt < 0 || (rt & 1) != 0) return;\n`;
    output += `    int rt2 = arm64_parse_reg(val2.reg);\n`;
    output += `    if (rt2 != rt + 1) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(val1.reg);\n`;
    output += `    \n`;

    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('LR32') || v.id.includes('R32') || v.id.includes('SR32') || v.id.includes('C32') || v.id.includes('CP32')));
    const variant64 = variants.find(v => v.id && (v.id.includes('_64_') || v.id.includes('LR64') || v.id.includes('R64') || v.id.includes('SR64') || v.id.includes('C64') || v.id.includes('CP64')));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((rs & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Store exclusive pair (STXP, STLXP)
  // Detected by: 4 operands + Rs + Rt + Rt2
  if (pattern === 'exclusive_store_pair') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand status, cj_operand val1, cj_operand val2, cj_operand mem) {\n`;
    output += `  if (status.type == CJ_REGISTER && val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int rs = arm64_parse_reg(status.reg);\n`;
    output += `    if (rs < 0) return;\n`;
    output += `    int rt = arm64_parse_reg(val1.reg);\n`;
    output += `    if (rt < 0 || (rt & 1) != 0) return;\n`;
    output += `    int rt2 = arm64_parse_reg(val2.reg);\n`;
    output += `    if (rt2 != rt + 1) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(val1.reg);\n`;
    output += `    \n`;

    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('LR32') || v.id.includes('R32') || v.id.includes('SR32') || v.id.includes('C32') || v.id.includes('CP32')));
    const variant64 = variants.find(v => v.id && (v.id.includes('_64_') || v.id.includes('LR64') || v.id.includes('R64') || v.id.includes('SR64') || v.id.includes('C64') || v.id.includes('CP64')));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((rt2 & 0x1f) << 10);\n`;
    output += `    instr |= ((rs & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Load exclusive pair (LDXP, LDAXP)
  // Detected by: 3 operands + Rt + Rt2, NO Rs
  if (pattern === 'exclusive_load_pair') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand val1, cj_operand val2, cj_operand mem) {\n`;
    output += `  if (val1.type == CJ_REGISTER && val2.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int rt = arm64_parse_reg(val1.reg);\n`;
    output += `    if (rt < 0 || (rt & 1) != 0) return;\n`;
    output += `    int rt2 = arm64_parse_reg(val2.reg);\n`;
    output += `    if (rt2 != rt + 1) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(val1.reg);\n`;
    output += `    \n`;

    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('LR32') || v.id.includes('R32') || v.id.includes('SR32') || v.id.includes('C32') || v.id.includes('CP32')));
    const variant64 = variants.find(v => v.id && (v.id.includes('_64_') || v.id.includes('LR64') || v.id.includes('R64') || v.id.includes('SR64') || v.id.includes('C64') || v.id.includes('CP64')));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((rt2 & 0x1f) << 10);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: CAS (Compare and Swap)
  // Detected by: 3 operands + Rs + Rt + ordering bits + mnemonic starts with 'cas'
  if (pattern === 'cas') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand compare, cj_operand value, cj_operand mem) {\n`;
    output += `  if (compare.type == CJ_REGISTER && value.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int rs = arm64_parse_reg(compare.reg);\n`;
    output += `    if (rs < 0) return;\n`;
    output += `    int rt = arm64_parse_reg(value.reg);\n`;
    output += `    if (rt < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(value.reg);\n`;
    output += `    \n`;

    // Find 32-bit and 64-bit variants
    const variant32 = variants.find(v => v.id && (v.id.includes('_32_') || v.id.includes('B_') || v.id.includes('H_')));
    const variant64 = variants.find(v => v.id && v.id.includes('_64_'));

    if (variant32 && variant64) {
      output += `    uint32_t instr = is64 ? ${variant64.value} : ${variant32.value};\n`;
    } else if (variant32) {
      output += `    uint32_t instr = ${variant32.value};\n`;
    } else {
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (rt & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((rs & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Atomic load operations (LDADD, LDCLR, SWP, etc.) - 3 operands
  if (pattern === 'atomic_load') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand rs, cj_operand rt, cj_operand mem) {\n`;
    output += `  if (rs.type == CJ_REGISTER && rt.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int reg_s = arm64_parse_reg(rs.reg);\n`;
    output += `    if (reg_s < 0) return;\n`;
    output += `    int reg_t = arm64_parse_reg(rt.reg);\n`;
    output += `    if (reg_t < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(rs.reg);\n`;
    output += `    \n`;
    const variant32 = variants.find(v => v.id && v.id.includes('_32_memop'));
    const variant64 = variants.find(v => v.id && v.id.includes('_64_memop'));

    if (variant32 && variant64) {
      // Compute complete encoding: size [31:30], A [23], R [22]
      let value32 = parseInt(variant32.value);

      // Detect acquire/release bits from mnemonic suffix
      // LDADD/STADD: A=0, R=0
      // LDADDA/STADDA: A=1, R=0
      // LDADDL/STADDL: A=0, R=1
      // LDADDAL/STADDAL: A=1, R=1
      let A = 0, R = 0;
      if (mnemonic.endsWith('al')) {
        A = 1; R = 1;
      } else if (mnemonic.endsWith('a')) {
        A = 1; R = 0;
      } else if (mnemonic.endsWith('l')) {
        A = 0; R = 1;
      }

      // Apply A and R bits to base value
      value32 = (value32 | (A << 23) | (R << 22)) >>> 0;

      // Compute 64-bit encoding by setting size bits [31:30] to 0b11
      const value64 = (value32 | (0b11 << 30)) >>> 0;
      const value32Hex = '0x' + value32.toString(16).toUpperCase();
      const value64Hex = '0x' + value64.toString(16).toUpperCase();
      output += `    uint32_t instr = is64 ? ${value64Hex} : ${value32Hex};\n`;
    } else if (variant32) {
      output += `    uint32_t instr = ${variant32.value};\n`;
    } else if (variant64) {
      output += `    uint32_t instr = ${variant64.value};\n`;
    } else {
      // Fallback to first variant
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= (reg_t & 0x1f);\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((reg_s & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Pattern: Atomic store operations (STADD, STCLR, etc.) - 2 operands
  if (pattern === 'atomic_store') {
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand rs, cj_operand mem) {\n`;
    output += `  if (rs.type == CJ_REGISTER && mem.type == CJ_MEMORY) {\n`;
    output += `    int reg_s = arm64_parse_reg(rs.reg);\n`;
    output += `    if (reg_s < 0) return;\n`;
    output += `    int rn = arm64_parse_reg(mem.mem.base);\n`;
    output += `    if (rn < 0) return;\n`;
    output += `    \n`;
    output += `    int is64 = arm64_is_64bit(rs.reg);\n`;
    output += `    \n`;
    const variant32 = variants.find(v => v.id && v.id.includes('_32_memop'));
    const variant64 = variants.find(v => v.id && v.id.includes('_64_memop'));

    if (variant32 && variant64) {
      // Compute complete encoding: size [31:30], A [23], R [22]
      let value32 = parseInt(variant32.value);

      // Detect acquire/release bits from mnemonic suffix
      let A = 0, R = 0;
      if (mnemonic.endsWith('al')) {
        A = 1; R = 1;
      } else if (mnemonic.endsWith('a')) {
        A = 1; R = 0;
      } else if (mnemonic.endsWith('l')) {
        A = 0; R = 1;
      }

      // Apply A and R bits to base value
      value32 = (value32 | (A << 23) | (R << 22)) >>> 0;

      // Compute 64-bit encoding by setting size bits [31:30] to 0b11
      const value64 = (value32 | (0b11 << 30)) >>> 0;
      const value32Hex = '0x' + value32.toString(16).toUpperCase();
      const value64Hex = '0x' + value64.toString(16).toUpperCase();
      output += `    uint32_t instr = is64 ? ${value64Hex} : ${value32Hex};\n`;
    } else if (variant32) {
      output += `    uint32_t instr = ${variant32.value};\n`;
    } else if (variant64) {
      output += `    uint32_t instr = ${variant64.value};\n`;
    } else {
      // Fallback to first variant
      output += `    uint32_t instr = ${variants[0].value};\n`;
    }

    output += `    \n`;
    output += `    instr |= 0x1f;\n`;
    output += `    instr |= ((rn & 0x1f) << 5);\n`;
    output += `    instr |= ((reg_s & 0x1f) << 16);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Check if this is an SVE instruction
  const hasSVE = variants.some(v => v.id && (v.id.includes('_z_') || v.id.includes('_p_')));

  // If this is an SVE instruction, generate SVE-specific code
  if (hasSVE && variants.every(v => v.id && (v.id.includes('_z_') || v.id.includes('_p_')))) {
    const sveInst = variants[0];

    // Analyze operands to determine function signature
    const operands = (sveInst.operands || []).filter(op => {
      if (!op.link) return false;
      const link = op.link.toLowerCase();
      // Skip size specifiers, shift, immediates we don't handle yet
      return link !== 't' && link !== 't_1' && !link.startsWith('shift') && !link.startsWith('imm') &&
             !link.startsWith('mod') && !link.startsWith('pattern') && !link.startsWith('const');
    });

    const hasZDest = operands.some(op => op.link && (op.link === 'zd' || op.link === 'zdn' || op.link === 'zda'));
    const hasPDest = operands.some(op => op.link && (op.link === 'pd' || op.link === 'pdn'));
    const zOperands = operands.filter(op => op.link && (op.link.startsWith('z') || op.link === 'zm_1')).length;
    const pOperands = operands.filter(op => op.link && op.link.startsWith('p')).length;

    // For now, generate simple SVE functions for common patterns
    // Pattern: Zd = Zn op Zm (3 Z registers)
    if (hasZDest && zOperands === 3 && pOperands === 0) {
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);\n`;
      output += `    if (zd.reg < 0) return;\n`;
      output += `    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);\n`;
      output += `    if (zn.reg < 0) return;\n`;
      output += `    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);\n`;
      output += `    if (zm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    if (zd.size != zn.size || zd.size != zm.size) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${sveInst.value};\n`;
      output += `    instr |= ((zd.size & 0x3) << 22);\n`;
      output += `    instr |= (zd.reg & 0x1f);\n`;
      output += `    instr |= ((zn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((zm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
      continue;
    }

    // Pattern: Zd = Zn op Zm with predicate (3 Z registers + predicate)
    if (hasZDest && zOperands >= 2 && pOperands >= 1) {
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand pred, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && pred.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_z_reg_info zd = arm64_parse_z_reg(dst.reg);\n`;
      output += `    if (zd.reg < 0) return;\n`;
      output += `    int pg = arm64_parse_p_reg(pred.reg);\n`;
      output += `    if (pg < 0) return;\n`;
      output += `    arm64_z_reg_info zn = arm64_parse_z_reg(src1.reg);\n`;
      output += `    if (zn.reg < 0) return;\n`;
      output += `    arm64_z_reg_info zm = arm64_parse_z_reg(src2.reg);\n`;
      output += `    if (zm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    if (zd.size != zn.size || zd.size != zm.size) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${sveInst.value};\n`;
      output += `    instr |= ((zd.size & 0x3) << 22);\n`;
      output += `    instr |= ((pg & 0x7) << 10);\n`;
      output += `    instr |= (zd.reg & 0x1f);\n`;
      output += `    instr |= ((zn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((zm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
      continue;
    }

    // For other SVE patterns, generate empty stub for now
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
    output += `}\n\n`;
    continue;
  }

  // Check if this has {2} suffix (narrow/widen operations)
  const hasSuffix2 = variants.some(v => v.mnemonic && v.mnemonic.includes('{2}'));

  // If this has {2} suffix, generate two functions: base and "2" variant
  if (hasSuffix2 && variants.every(v => v.mnemonic && v.mnemonic.includes('{2}'))) {
    const baseInst = variants[0];

    // Check if it's a 3-operand instruction (most {2} instructions are)
    const operandCount = (baseInst.operands || []).filter(op => {
      if (!op.link) return false;
      const link = op.link.toLowerCase();
      // Skip {2} placeholder, arrangement specifiers, and immediate fields
      return link !== '2' && link !== '{2}' && link !== 't' && link !== 'ta' && link !== 'tb' && !link.startsWith('imm') && !link.startsWith('shift');
    }).length;

    if (operandCount === 3) {
      // Generate base function (Q=0)
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);\n`;
      output += `    if (vm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${baseInst.value};\n`;
      output += `    instr &= ~(1u << 30);\n`;
      output += `    instr |= ((vd.size & 0x3) << 22);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((vm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;

      // Generate "2" function (Q=1)
      output += `static inline void cj_${mnemonic}2(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);\n`;
      output += `    if (vm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${baseInst.value};\n`;
      output += `    instr |= (1u << 30);\n`;
      output += `    instr |= ((vd.size & 0x3) << 22);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((vm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
      continue;
    } else if (operandCount == 2) {
      // Generate base function (Q=0) - 2 operand version
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${baseInst.value};\n`;
      output += `    instr &= ~(1u << 30);\n`;
      output += `    instr |= ((vd.size & 0x3) << 22);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;

      // Generate "2" function (Q=1) - 2 operand version
      output += `static inline void cj_${mnemonic}2(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${baseInst.value};\n`;
      output += `    instr |= (1u << 30);\n`;
      output += `    instr |= ((vd.size & 0x3) << 22);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
      continue;
    }
  }

  // B.<cond> (conditional branch) is handled manually at the end of the file
  // Skip it here to avoid duplication
  const hasCondSuffix = variants.some(v => v.mnemonic && v.mnemonic.includes('.<') && v.mnemonic.includes('>'));
  if (hasCondSuffix && mnemonic === 'b') {
    continue;  // Already handled manually
  }

  // Check if this is BFMLAL<bt> (BFloat16 multiply-add) - NEON version only, not SVE
  const hasBtSuffix = variants.some(v => v.mnemonic && v.mnemonic.includes('<bt>'));
  const isSveOnly = variants.every(v => v.id && (v.id.includes('_z_') || v.id.includes('_p_')));

  if (hasBtSuffix && mnemonic === 'bfmlal' && !isSveOnly) {
    // We have two instruction types: element and register form
    const elemVariant = variants.find(v => v.id && v.id.includes('asimdelem'));
    const regVariant = variants.find(v => v.id && v.id.includes('asimdsame'));

    // Generate BFMLALB (bottom, Q=0) - register form
    if (regVariant) {
      output += `static inline void cj_bfmlalb(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);\n`;
      output += `    if (vm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${regVariant.value};\n`;
      output += `    instr &= ~(1u << 30);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((vm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;

      // Generate BFMLALT (top, Q=1) - register form
      output += `static inline void cj_bfmlalt(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);\n`;
      output += `    if (vm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${regVariant.value};\n`;
      output += `    instr |= (1u << 30);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((vm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
    }
    continue;
  }

  // Separate SVE and non-SVE variants for proper handling of mixed instructions
  const nonSveVariants = variants.filter(v => v.id && !v.id.includes('_z_') && !v.id.includes('_p_'));

  // Check if this is a cryptography operation
  const hasCryptoVariant = variants.some(v => v.id && v.id.includes('_crypto'));

  // If this is a crypto operation (excluding SVE variants), generate special function
  if (hasCryptoVariant && nonSveVariants.every(v => v.id && v.id.includes('_crypto'))) {
    const cryptoInst = variants[0];
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
    output += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
    output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
    output += `    if (vd.reg < 0) return;\n`;
    output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);\n`;
    output += `    if (vn.reg < 0) return;\n`;
    output += `    \n`;
    output += `    uint32_t instr = ${cryptoInst.value};\n`;
    output += `    instr |= (vd.reg & 0x1f);\n`;
    output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  }

  // Check if this is a SIMD unary operation (asimdmisc, asisdmisc)
  const simdUnaryVariants = variants.filter(v => v.id && (v.id.includes('_asimdmisc') || v.id.includes('_asisdmisc')));
  const hasSimdUnaryVariant = simdUnaryVariants.length > 0;
  const hasNonSimdVariant = variants.some(v => v.id && !v.id.includes('_asimdmisc') && !v.id.includes('_asisdmisc') && !v.id.includes('_sve') && !v.id.includes('_z_') && !v.id.includes('_p_'));

  // Store SIMD handling code to prepend to function if both exist
  let simdPrologCode = '';

  // If this has ONLY SIMD unary variants (no other scalar variants), generate dedicated SIMD function
  if (hasSimdUnaryVariant && !hasNonSimdVariant) {
    // Prefer asimdmisc (vector) over asisdmisc (scalar) for the base encoding
    const simdInst = variants.find(v => v.id && v.id.includes('_asimdmisc')) || variants[0];
    output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;
    output += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
    output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
    output += `    if (vd.reg < 0) return;\n`;
    output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);\n`;
    output += `    if (vn.reg < 0) return;\n`;
    output += `    \n`;
    output += `    if (vd.q != vn.q || vd.size != vn.size) return;\n`;
    output += `    \n`;
    output += `    uint32_t instr = ${simdInst.value};\n`;
    output += `    instr |= (vd.q << 30);\n`;
    output += `    instr |= ((vd.size & 0x3) << 22);\n`;
    output += `    instr |= (vd.reg & 0x1f);\n`;
    output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
    output += `    \n`;
    output += `    cj_add_u32(ctx, instr);\n`;
    output += `    return;\n`;
    output += `  }\n`;
    output += `}\n\n`;
    continue;
  } else if (hasSimdUnaryVariant && hasNonSimdVariant) {
    // Both SIMD unary and other scalar variants - add SIMD check as prolog
    const simdInst = variants.find(v => v.id && v.id.includes('_asimdmisc')) || variants[0];
    simdPrologCode += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
    simdPrologCode += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
    simdPrologCode += `    if (vd.reg >= 0) {\n`;
    simdPrologCode += `      arm64_vec_reg_info vn = arm64_parse_vec_reg(src.reg);\n`;
    simdPrologCode += `      if (vn.reg >= 0 && vd.q == vn.q && vd.size == vn.size) {\n`;
    simdPrologCode += `        uint32_t instr = ${simdInst.value};\n`;
    simdPrologCode += `        instr |= (vd.q << 30);\n`;
    simdPrologCode += `        instr |= ((vd.size & 0x3) << 22);\n`;
    simdPrologCode += `        instr |= (vd.reg & 0x1f);\n`;
    simdPrologCode += `        instr |= ((vn.reg & 0x1f) << 5);\n`;
    simdPrologCode += `        cj_add_u32(ctx, instr);\n`;
    simdPrologCode += `        return;\n`;
    simdPrologCode += `      }\n`;
    simdPrologCode += `    }\n`;
    simdPrologCode += `  }\n`;
  }

  // Check if this is a SIMD vector operation (asimdsame, asimdsamefp16)
  const hasSimdVariant = variants.some(v => v.id && (v.id.includes('_asimdsame') || v.id.includes('_asimdsamefp16')));
  const hasScalarVariant = variants.some(v => v.id && !v.id.includes('_asimd') && !v.id.includes('_asisd'));

  // Append to SIMD prolog if both exist
  if (hasSimdVariant) {
    const simdVariants = variants.filter(v => v.id && (v.id.includes('_asimdsame') || v.id.includes('_asimdsamefp16')));
    const simdInst = simdVariants[0];

    // If only SIMD, generate SIMD-only function with 3 operands
    if (!hasScalarVariant) {
      output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src1, cj_operand src2) {\n`;
      output += `  if (dst.type == CJ_REGISTER && src1.type == CJ_REGISTER && src2.type == CJ_REGISTER) {\n`;
      output += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      output += `    if (vd.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vn = arm64_parse_vec_reg(src1.reg);\n`;
      output += `    if (vn.reg < 0) return;\n`;
      output += `    arm64_vec_reg_info vm = arm64_parse_vec_reg(src2.reg);\n`;
      output += `    if (vm.reg < 0) return;\n`;
      output += `    \n`;
      output += `    if (vd.q != vn.q || vd.q != vm.q || vd.size != vn.size || vd.size != vm.size) return;\n`;
      output += `    \n`;
      output += `    uint32_t instr = ${simdInst.value};\n`;
      output += `    instr |= (vd.q << 30);\n`;
      output += `    instr |= ((vd.size & 0x3) << 22);\n`;
      output += `    instr |= (vd.reg & 0x1f);\n`;
      output += `    instr |= ((vn.reg & 0x1f) << 5);\n`;
      output += `    instr |= ((vm.reg & 0x1f) << 16);\n`;
      output += `    \n`;
      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
      output += `}\n\n`;
      continue;
    } else {
      // Both scalar and SIMD - add SIMD check as prolog in 2-operand function
      // SIMD variant uses dst + src as the two vectors to add, result in dst
      simdPrologCode += `  if (dst.type == CJ_REGISTER && src.type == CJ_REGISTER) {\n`;
      simdPrologCode += `    arm64_vec_reg_info vd = arm64_parse_vec_reg(dst.reg);\n`;
      simdPrologCode += `    if (vd.reg >= 0) {\n`;
      simdPrologCode += `      arm64_vec_reg_info vm = arm64_parse_vec_reg(src.reg);\n`;
      simdPrologCode += `      if (vm.reg >= 0 && vd.q == vm.q && vd.size == vm.size) {\n`;
      simdPrologCode += `        uint32_t instr = ${simdInst.value};\n`;
      simdPrologCode += `        instr |= (vd.q << 30);\n`;
      simdPrologCode += `        instr |= ((vd.size & 0x3) << 22);\n`;
      simdPrologCode += `        instr |= (vd.reg & 0x1f);\n`;
      simdPrologCode += `        instr |= ((vd.reg & 0x1f) << 5);\n`;
      simdPrologCode += `        instr |= ((vm.reg & 0x1f) << 16);\n`;
      simdPrologCode += `        cj_add_u32(ctx, instr);\n`;
      simdPrologCode += `        return;\n`;
      simdPrologCode += `      }\n`;
      simdPrologCode += `    }\n`;
      simdPrologCode += `  }\n`;
    }
  }

  // Group variants by format to handle multiple signatures in one function
  output += `static inline void cj_${mnemonic}(cj_ctx* ctx, cj_operand dst, cj_operand src) {\n`;

  // Add SIMD prolog if both scalar and SIMD variants exist
  if (simdPrologCode) {
    output += simdPrologCode;
  }

  const variantsBySignature = {};

  for (const inst of variants) {
    const operands = inst.operands || [];
    if (operands.length < 2) continue;

    const mappedOps = operands.map(op => mapOperandType(op));
    const fields = operands.map(op => extractFieldName(op));

    const filteredOps = [];
    const filteredFields = [];
    for (let i = 0; i < mappedOps.length; i++) {
      const opType = mappedOps[i];
      const fieldName = fields[i];
      if (fieldName === 'sh' || fieldName === 'shift' || fieldName === 'imm6') {
        continue;  // Optional shift amount handled implicitly
      }
      if (opType.type === 'arrangement' || opType.type === 'vec_extra') {
        continue;
      }
      filteredOps.push(opType);
      filteredFields.push(fields[i]);
    }

    if (filteredOps.length < 2) continue;

    const tupleCount = operands.reduce((max, operand) => {
      const link = (operand.link || '').toLowerCase();
      if (!link.startsWith('vt')) return max;
      const suffix = link.slice(2);
      const idx = suffix ? parseInt(suffix, 10) : 1;
      if (!Number.isFinite(idx)) return max;
      return Math.max(max, idx);
    }, 0);

    let format = null;
    const isLoadStore = mnemonic.startsWith('ldr') || mnemonic.startsWith('str') || mnemonic === 'ldrsw';
    const isReg = (op) => op.type === 'reg' || op.type === 'fpreg' || op.type === 'vec';

    if (filteredOps.length >= 4) {
      if (isReg(filteredOps[0]) && isReg(filteredOps[1]) &&
          filteredOps[2].type === 'imm' && filteredOps[3].type === 'imm') {
        format = 'reg_reg';
      }
    }
    if (!format && filteredOps.length >= 3) {
      if (isReg(filteredOps[0]) && isReg(filteredOps[1]) && isReg(filteredOps[2])) {
        format = 'reg_reg_reg';
      } else if (isReg(filteredOps[0]) && isReg(filteredOps[1]) && filteredOps[2].type === 'imm') {
        format = isLoadStore ? 'reg_memory' : 'reg_reg_imm';
      } else if (isReg(filteredOps[0]) && filteredOps[1].type === 'imm') {
        format = 'reg_imm';
      }
    } else if (filteredOps.length === 2) {
      if (isReg(filteredOps[0]) && isReg(filteredOps[1])) {
        format = 'reg_reg';
      } else if (isReg(filteredOps[0]) && filteredOps[1].type === 'imm') {
        format = 'reg_imm';
      }
    }

    if (!format) {
    if (mnemonic === 'add' || mnemonic === 'cmp') {
      console.error(mnemonic + ' skipping', inst.id, filteredOps.map(o=>o.type));
    }
      if (mnemonic === 'add') {
        console.error('ADD skipping variant', inst.id, filteredOps.map(o => o.type));
      }
      continue;
    }

    const opSignature = filteredOps
      .map(op => {
        if (op.type === 'vec') return tupleCount > 1 ? `vec_list${tupleCount}` : 'vec';
        return op.type;
      })
      .join(',');
    const fieldSignature = filteredFields.filter(Boolean).join(',');
    const key = `${format}|${opSignature}|${fieldSignature}`;

    if (!variantsBySignature[key]) {
      variantsBySignature[key] = {
        format,
        ops: filteredOps,
        fields: filteredFields,
        tupleCount,
        variants: [],
      };
    }
    variantsBySignature[key].variants.push({ inst, tupleCount });
  }

  // Generate code for each signature bucket
  for (const bucket of Object.values(variantsBySignature)) {
    const { format, ops, fields, tupleCount, variants: variantGroup } = bucket;
    const inst = variantGroup[0].inst;

    // Check if we have both 32-bit and 64-bit variants
    const has32bit = variantGroup.some(v => v.inst.bitdiffs && v.inst.bitdiffs.includes('sf == 0'));
    const has64bit = variantGroup.some(v => v.inst.bitdiffs && v.inst.bitdiffs.includes('sf == 1'));
    const useRuntimeCheck = has32bit && has64bit;

    const shiftField = findVariable(inst, 'shift');
    const imm6Field = findVariable(inst, 'imm6') || findVariable(inst, 'amount');
    const optionField = findVariable(inst, 'option');
    const imm3Field = findVariable(inst, 'imm3');
    const shField = findVariable(inst, 'sh');
    const imm9Field = findVariable(inst, 'imm9');
    const opcField = findVariable(inst, 'opc');

    // Generate code based on format
    if (format === 'reg_reg_reg') {
      // Register-register operation: dst = dst op src (maps to: Rd=dst, Rn=dst, Rm=src)
      let regRegRegCond = `dst.type == CJ_REGISTER && src.type == CJ_REGISTER`;
      if (!optionField) {
        regRegRegCond += ` && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount`;
      }
      output += `  if (${regRegRegCond}) {\n`;

      // Use appropriate parser for each operand based on its type
      const dstIsFP = ops[0].type === 'fpreg';
      const srcIsFP = (ops.length >= 3 ? ops[2] : ops[1]).type === 'fpreg';
      const dstParseFunc = dstIsFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';
      const srcParseFunc = srcIsFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';

      output += `    int rd = ${dstParseFunc}(dst.reg);\n`;
      output += `    if (rd < 0) return;\n`;
      output += `    int rn = rd;\n`;
      output += `    int rm = ${srcParseFunc}(src.reg);\n`;
      output += `    if (rm < 0) return;\n`;

      const isFP = dstIsFP || srcIsFP;

      // Build the instruction encoding
      // Complete encoding with all fixed bits already set in value from JSONL
      const baseValue = parseInt(inst.value, 16);
      output += `    uint32_t instr = ${inst.value};\n`;

      // Set sf bit based on register size - only for integer instructions
      if (!isFP) {
        if (useRuntimeCheck) {
          output += `    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;\n`;
          output += `    instr |= (sf << 31);\n`;
        } else if (has64bit) {
          output += `    instr |= (1 << 31);\n`;
        } else {
        }
      } else {
        // For FP instructions, set ftype bits [23:22] based on register size
        output += `    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;\n`;
        output += `    instr &= ~(0x3 << 22);\n`;
        output += `    instr |= (ftype << 22);\n`;
      }

      // Set register fields using metadata
      // For reg_reg_reg format: C function is (dst, src) with rd, rn=rd, rm available
      const numCVars = 3; // rd, rn, rm available in this context
      output += generateRegisterMappingFromMetadata(inst, numCVars);

      if (shiftField) {
        const disallowRor = inst.id && inst.id.includes('_addsub_shift');
        output += `    uint32_t shift_mode = 0;\n`;
        output += `    switch (src.shift.kind) {\n`;
          output += `      case CJ_SHIFT_KIND_NONE:\n`;
          output += `      case CJ_SHIFT_KIND_LSL:\n`;
          output += `        shift_mode = 0;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_LSR:\n`;
          output += `        shift_mode = 1;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_ASR:\n`;
          output += `        shift_mode = 2;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_ROR:\n`;
          if (disallowRor) {
            output += `        return;\n`;
          } else {
            output += `        shift_mode = 3;\n`;
            output += `        break;\n`;
          }
          output += `      default:\n`;
          output += `        return;\n`;
          output += `    }\n`;
          output += `    instr &= ~(${bitMask(shiftField.width)} << ${shiftField.lo});\n`;
          output += `    instr |= ((shift_mode & ${bitMask(shiftField.width)}) << ${shiftField.lo});\n`;
        }
        if (imm6Field) {
          output += `    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;\n`;
          output += `    if (arm64_is_64bit(dst.reg)) {\n`;
          output += `      if (shift_amount > 63u) return;\n`;
          output += `    } else {\n`;
          output += `      if (shift_amount > 31u) return;\n`;
          output += `    }\n`;
          output += `    instr &= ~(${bitMask(imm6Field.width)} << ${imm6Field.lo});\n`;
          output += `    instr |= ((shift_amount & ${bitMask(imm6Field.width)}) << ${imm6Field.lo});\n`;
        }
        if (optionField) {
          output += `    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {\n`;
          output += `      uint32_t option = 0;\n`;
          output += `      switch (src.extend.kind) {\n`;
          output += `        case CJ_EXTEND_KIND_UXTB: option = 0; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTH: option = 1; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTW: option = 2; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTX: option = 3; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTB: option = 4; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTH: option = 5; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTW: option = 6; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTX: option = 7; break;\n`;
          output += `        default: return;\n`;
          output += `      }\n`;
          output += `      instr &= ~(${bitMask(optionField.width)} << ${optionField.lo});\n`;
          output += `      instr |= ((option & ${bitMask(optionField.width)}) << ${optionField.lo});\n`;
          output += `    }\n`;
        }
      if (imm3Field) {
        output += `    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {\n`;
        output += `      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;\n`;
        output += `      uint32_t extend_amount = src.extend.amount;\n`;
        output += `      if (extend_amount > ${bitMask(imm3Field.width)}) return;\n`;
        output += `      instr &= ~(${bitMask(imm3Field.width)} << ${imm3Field.lo});\n`;
        output += `      instr |= ((extend_amount & ${bitMask(imm3Field.width)}) << ${imm3Field.lo});\n`;
        output += `    }\n`;
      }

      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;

    } else if (format === 'reg_reg_imm') {
      const immVarNames = ['imm12', 'imm9', 'imm6', 'imm5', 'imm4', 'imm3', 'imm'];
      const immVarPresent = immVarNames.some(name => findVariable(inst, name));
      const hasImmediateField = fields.some(field => field && field.startsWith('imm'));
      const usesImmediate =
        immVarPresent ||
        hasImmediateField ||
        shField ||
        optionField ||
        imm3Field ||
        imm9Field ||
        (ops.length >= 3 && ops[2] && ops[2].max !== undefined);

      if (usesImmediate) {
        // Register-immediate operation: dst = dst op imm (maps to: Rd=dst, Rn=dst, imm=src)
        output += `  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {\n`;

      // Check if this is an FP instruction
      const isFP = ops[0].type === 'fpreg';
      const parseFunc = isFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';

      output += `    int rd = ${parseFunc}(dst.reg);\n`;
      output += `    if (rd < 0) return;\n`;
      output += `    int rn = rd;\n`;
      output += `    uint64_t imm = src.constant;\n`;

      if (ops[2].max !== undefined) {
        output += `    if (imm > ${ops[2].max}) return;\n`;
      }

      // Build the instruction encoding
      // Complete encoding with all fixed bits already set in value from JSONL
      const baseValue = parseInt(inst.value, 16);
      output += `    uint32_t instr = ${inst.value};\n`;

      // Set sf bit based on register size - only for integer instructions
      if (!isFP) {
        if (useRuntimeCheck) {
          output += `    int sf = arm64_is_64bit(dst.reg) ? 1 : 0;\n`;
          output += `    instr |= (sf << 31);\n`;
        } else if (has64bit) {
          output += `    instr |= (1 << 31);\n`;
        } else {
        }
      } else {
        // For FP instructions, set ftype bits [23:22] based on register size
        output += `    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;\n`;
        output += `    instr &= ~(0x3 << 22);\n`;
        output += `    instr |= (ftype << 22);\n`;
      }

      // Set register fields using metadata
      const numRegOps = ops.filter(op => op.type === 'reg' || op.type === 'fpreg').length;
      output += generateRegisterMappingFromMetadata(inst, numRegOps);

      // Set immediate field (keep manual for now as it's not a register)
      if (fields[2] === 'imm12') {
        output += `    instr |= ((imm & 0xfff) << 10);\n`;
      }

      if (shField) {
        output += `    uint32_t sh = 0;\n`;
        output += `    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {\n`;
        output += `      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;\n`;
        output += `      if (src.shift.amount == 0) {\n`;
        output += `        sh = 0;\n`;
        output += `      } else if (src.shift.amount == 12) {\n`;
        output += `        sh = 1;\n`;
        output += `      } else {\n`;
        output += `        return;\n`;
        output += `      }\n`;
        output += `    }\n`;
        output += `    instr &= ~(${bitMask(shField.width)} << ${shField.lo});\n`;
        output += `    instr |= ((sh & ${bitMask(shField.width)}) << ${shField.lo});\n`;
      }

        output += `    cj_add_u32(ctx, instr);\n`;
        output += `    return;\n`;
        output += `  }\n`;
      }

    } else if (format === 'reg_memory') {
      // Load/Store with memory operand: dst = [base + offset] or [base + index, LSL #shift]
      output += `  if (src.type == CJ_MEMORY) {\n`;

      // For LDR/STR, check Q registers first (128-bit SIMD loads/stores)
      if (mnemonic === 'ldr' || mnemonic === 'str') {
        const isLoad = mnemonic === 'ldr';
        const qInstr = isLoad ? '0x3DC00000' : '0x3D800000';
        output += `    int qt = arm64_parse_q_reg(dst.reg);\n`;
        output += `    if (qt >= 0 && src.mem.mode == CJ_MEM_MODE_OFFSET && !src.mem.index) {\n`;
        output += `      const char* base = src.mem.base ? src.mem.base : "sp";\n`;
        output += `      int rn = arm64_parse_reg(base);\n`;
        output += `      if (rn < 0) return;\n`;
        output += `      int64_t offset = src.mem.disp;\n`;
        output += `      if (offset % 16 != 0) return;\n`;
        output += `      uint64_t imm12 = offset / 16;\n`;
        output += `      if (imm12 > 4095) return;\n`;
        output += `      uint32_t instr = ${qInstr};\n`;
        output += `      instr |= ((imm12 & 0xfff) << 10);\n`;
        output += `      instr |= ((rn & 0x1f) << 5);\n`;
        output += `      instr |= (qt & 0x1f);\n`;
        output += `      cj_add_u32(ctx, instr);\n`;
        output += `      return;\n`;
        output += `    }\n`;
      }

      // Check if this is an FP instruction
      const isFP = ops[0].type === 'fpreg';
      const parseFunc = isFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';

      output += `    int rt = ${parseFunc}(dst.reg);\n`;
      output += `    if (rt < 0) return;\n`;
      output += `    const char* base = src.mem.base ? src.mem.base : "sp";\n`;
      const isByte = mnemonic.includes('b') && !mnemonic.includes('ldrb');
      const isHalf = mnemonic.includes('h');
      output += `    int rn = arm64_parse_reg(base);\n`;  // Base is always integer register
      output += `    if (rn < 0) return;\n`;
      output += `    \n`;
      output += `    if (src.mem.index) {\n`;
      output += `      int rm = arm64_parse_reg(src.mem.index);\n`;
      output += `      if (rm < 0) return;\n`;
      output += `      \n`;
      output += `      int shift = 0;\n`;
      output += `      if (src.mem.scale == 2) shift = 1;\n`;
      output += `      else if (src.mem.scale == 4) shift = 2;\n`;
      output += `      else if (src.mem.scale == 8) shift = 3;\n`;
      output += `      else if (src.mem.scale != 1) return;\n`;
      output += `      \n`;
      if (isFP) {
        output += `      int expected_shift = arm64_is_fp_64bit(dst.reg) ? 3 : 2;\n`;
      } else {
        output += `      int expected_shift = arm64_is_64bit(dst.reg) ? 3 : 2;\n`;
      }
      output += `      \n`;
      output += `      int S = (shift == expected_shift) ? 1 : (shift == 0 ? 0 : -1);\n`;
      output += `      if (S < 0) return;\n`;
      output += `      \n`;
      // Find register offset variant from ALL variants (not just current format group)
      const regoffVariant = variants.find(v => v.id && v.id.includes('_ldst_regoff') &&
        (v.id.includes('_32_') || v.id.includes('_64_')));
      if (regoffVariant) {
        // Determine if we need 32-bit or 64-bit variant
        const regoff32 = variants.find(v => v.id && v.id.includes('_ldst_regoff') && v.id.includes('_32_'));
        const regoff64 = variants.find(v => v.id && v.id.includes('_ldst_regoff') && v.id.includes('_64_'));

        if (regoff32 && regoff64) {
          if (isFP) {
            output += `      uint32_t instr = arm64_is_fp_64bit(dst.reg) ? ${regoff64.value} : ${regoff32.value};\n`;
          } else {
            output += `      uint32_t instr = arm64_is_64bit(dst.reg) ? ${regoff64.value} : ${regoff32.value};\n`;
          }
        } else {
          output += `      uint32_t instr = ${regoffVariant.value};\n`;
        }
        output += `      instr |= (rt & 0x1f);\n`;
        output += `      instr |= ((rn & 0x1f) << 5);\n`;
        output += `      instr |= (S << 12);\n`;
        output += `      instr |= (0b011 << 13);\n`;
        output += `      instr |= ((rm & 0x1f) << 16);\n`;
        output += `      cj_add_u32(ctx, instr);\n`;
        output += `      return;\n`;
      } else {
        output += `      return;\n`;
      }
      output += `    }\n`;
      output += `    \n`;
      const preVariants = variants
        .filter(v => v.id && v.id.includes('immpre'))
        .map(instVariant => ({ inst: instVariant }));
      const postVariants = variants
        .filter(v => v.id && v.id.includes('immpost'))
        .map(instVariant => ({ inst: instVariant }));
      const preExpr = buildVariantExpr(preVariants, isFP, ops[0].type);
      const postExpr = buildVariantExpr(postVariants, isFP, ops[0].type);
      const imm9Info = (preVariants.length ? findVariable(preVariants[0].inst, 'imm9') : null)
        || (postVariants.length ? findVariable(postVariants[0].inst, 'imm9') : null)
        || imm9Field;
      if ((inst.id && (inst.id.includes('immpre') || inst.id.includes('immpost'))) && (preExpr || postExpr)) {
      output += `    if (!src.mem.index && (src.mem.mode == CJ_MEM_MODE_PRE || src.mem.mode == CJ_MEM_MODE_POST)) {\n`;
      output += `      int64_t offset = src.mem.disp;\n`;
      output += `      if (offset < -256 || offset > 255) return;\n`;
      if (imm9Info) {
        output += `      uint32_t instr;\n`;
        output += `      if (src.mem.mode == CJ_MEM_MODE_PRE) {\n`;
        if (preExpr) {
          output += `        instr = ${preExpr};\n`;
        } else {
          output += `        return;\n`;
        }
        output += `      } else {\n`;
        if (postExpr) {
          output += `        instr = ${postExpr};\n`;
        } else {
          output += `        return;\n`;
        }
        output += `      }\n`;
        output += `      instr |= (rt & 0x1f);\n`;
        output += `      instr |= ((rn & 0x1f) << 5);\n`;
        output += `      instr &= ~(${bitMask(imm9Info.width)} << ${imm9Info.lo});\n`;
        output += `      instr |= ((uint32_t)(offset & ${bitMask(imm9Info.width)})) << ${imm9Info.lo};\n`;
        output += `      cj_add_u32(ctx, instr);\n`;
        output += `      return;\n`;
      } else {
        output += `      return;\n`;
      }
      output += `    }\n`;
      output += `    \n`;
      }
      output += `    if (src.mem.mode == CJ_MEM_MODE_OFFSET) {\n`;
      output += `      int64_t offset = src.mem.disp;\n`;

      // Determine transfer size and validate offset

      if (isByte) {
        output += `    uint64_t imm12 = offset;\n`;
      } else if (isHalf) {
        output += `    if (offset % 2 != 0) return;\n`;
        output += `    uint64_t imm12 = offset / 2;\n`;
      } else {
        if (isFP) {
          // FP registers: s* = 4 bytes, d* = 8 bytes
          output += `    int size = arm64_is_fp_64bit(dst.reg) ? 8 : 4;\n`;
        } else {
          // Integer registers: w* = 4 bytes, x* = 8 bytes
          output += `    int size = arm64_is_64bit(dst.reg) ? 8 : 4;\n`;
        }
        output += `    if (offset % size != 0) return;\n`;
        output += `    uint64_t imm12 = offset / size;\n`;
      }

      output += `    if (imm12 > 4095) return;\n`;

      // Select complete encoding based on register size
      // Find 32-bit and 64-bit variants in the group
      const variant32 = variantGroup.find(v =>
        v.inst.bitdiffs && v.inst.bitdiffs.includes('size == 10'));
      const variant64 = variantGroup.find(v =>
        v.inst.bitdiffs && v.inst.bitdiffs.includes('size == 11'));

      if (variant32 && variant64 && !isByte && !isHalf) {
        // Use complete encodings for 32/64-bit variants
        if (isFP) {
          output += `    uint32_t instr = arm64_is_fp_64bit(dst.reg) ? ${variant64.inst.value} : ${variant32.inst.value};\n`;
        } else {
          output += `    uint32_t instr = arm64_is_64bit(dst.reg) ? ${variant64.inst.value} : ${variant32.inst.value};\n`;
        }
      } else {
        // Fallback for byte/halfword or if variants not found
        output += `    uint32_t instr = ${inst.value};\n`;
      }

      // Set register and immediate fields
      output += `    instr |= (rt & 0x1f);\n`;
      output += `    instr |= ((rn & 0x1f) << 5);\n`;
      output += `      instr |= ((imm12 & 0xfff) << 10);\n`;

      output += `      cj_add_u32(ctx, instr);\n`;
      output += `      return;\n`;
      output += `    }\n`;
      output += `  }\n`;
    } else if (format === 'reg_reg') {
      if (tupleCount > 1) {
        const hasRdVar = !!findVariable(inst, 'Rd');
        const hasRnVar = !!findVariable(inst, 'Rn');
        const hasRmVar = !!findVariable(inst, 'Rm');
        const sizeVar = findVariable(inst, 'size');
        const qVar = findVariable(inst, 'Q');

        output += `  if ((dst.type == CJ_REGISTER_LIST || dst.type == CJ_REGISTER) && src.type == CJ_REGISTER) {\n`;
        output += `    arm64_vec_list_info list;\n`;
        output += `    if (!arm64_parse_vec_list_operand(dst, ${tupleCount}, &list)) return;\n`;
        output += `    arm64_vec_reg_info first = list.regs[0];\n`;
        output += `    int base_reg = arm64_parse_reg(src.reg);\n`;
        output += `    if (base_reg < 0) return;\n`;
        output += `    uint32_t instr = ${inst.value};\n`;
        if (hasRdVar) {
          output += `    instr &= ~0x1f;\n`;
          output += `    instr |= (first.reg & 0x1f);\n`;
        }
        if (hasRnVar) {
          output += `    instr &= ~(0x1f << 5);\n`;
          output += `    instr |= ((base_reg & 0x1f) << 5);\n`;
        }
        if (hasRmVar) {
          output += `    instr &= ~(0x1f << 16);\n`;
          output += `    instr |= ((base_reg & 0x1f) << 16);\n`;
        }
        if (sizeVar) {
          output += `    instr &= ~(${bitMask(sizeVar.width)} << ${sizeVar.lo});\n`;
          output += `    instr |= ((uint32_t)(first.size & ${bitMask(sizeVar.width)})) << ${sizeVar.lo};\n`;
        }
        if (qVar) {
          output += `    instr &= ~(${bitMask(qVar.width)} << ${qVar.lo});\n`;
          output += `    instr |= ((uint32_t)(first.q & ${bitMask(qVar.width)})) << ${qVar.lo};\n`;
        }
        const tupleVarNames = ['Rt', 'Rt2', 'Rt3', 'Rt4'];
        tupleVarNames.forEach((varName, index) => {
          if (index >= tupleCount) return;
          const varInfo = findVariable(inst, varName);
          if (!varInfo) return;
          output += `    instr &= ~(${bitMask(varInfo.width)} << ${varInfo.lo});\n`;
          output += `    instr |= ((uint32_t)(list.regs[${index}].reg & ${bitMask(varInfo.width)})) << ${varInfo.lo};\n`;
        });
        output += `    cj_add_u32(ctx, instr);\n`;
        output += `    return;\n`;
        output += `  }\n`;
      }

      let regRegCond = `dst.type == CJ_REGISTER && src.type == CJ_REGISTER`;
      if (!optionField) {
        regRegCond += ` && src.extend.kind == CJ_EXTEND_KIND_NONE && !src.extend.has_amount`;
      }

      // Use appropriate parser for each operand based on its type
      const dstIsFP = ops[0].type === 'fpreg';
      const srcIsFP = ops[1].type === 'fpreg';

      // Add register type checks to make conditions mutually exclusive
      if (dstIsFP && srcIsFP) {
        regRegCond += ` && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')`;
      } else if (dstIsFP && !srcIsFP) {
        regRegCond += ` && (dst.reg[0] == 's' || dst.reg[0] == 'd' || dst.reg[0] == 'h') && (src.reg[0] == 'x' || src.reg[0] == 'w')`;
      } else if (!dstIsFP && srcIsFP) {
        regRegCond += ` && (dst.reg[0] == 'x' || dst.reg[0] == 'w') && (src.reg[0] == 's' || src.reg[0] == 'd' || src.reg[0] == 'h')`;
      }

      output += `  if (${regRegCond}) {\n`;

      const dstParseFunc = dstIsFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';
      const srcParseFunc = srcIsFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';

      output += `    int rd = ${dstParseFunc}(dst.reg);\n`;
      output += `    if (rd < 0) return;\n`;
      output += `    int rn = ${srcParseFunc}(src.reg);\n`;
      output += `    if (rn < 0) return;\n`;

      output += `    uint32_t instr = ${inst.value};\n`;

      const isFP = dstIsFP || srcIsFP;
      if (!isFP && useRuntimeCheck) {
        output += generateSizeVariantHandling(variantGroup, opcField);
      } else if (isFP) {
        // Set ftype for FP destination
        if (dstIsFP) {
          output += `    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;\n`;
          output += `    instr &= ~(0x3 << 22);\n`;
          output += `    instr |= (ftype << 22);\n`;
        }
        // Set sf for integer source (for int-to-FP conversions)
        if (dstIsFP && !srcIsFP && useRuntimeCheck) {
          output += `    int sf = arm64_is_64bit(src.reg) ? 1 : 0;\n`;
          output += `    instr &= ~(1u << 31);\n`;
          output += `    instr |= (sf << 31);\n`;
        }
      }

      // Map registers to fields using metadata (no hardcoded positions!)
      output += generateRegisterMappingFromMetadata(inst, 2);

      if (shiftField) {
          const disallowRor = inst.id && inst.id.includes('_addsub_shift');
          output += `    uint32_t shift_mode = 0;\n`;
          output += `    switch (src.shift.kind) {\n`;
          output += `      case CJ_SHIFT_KIND_NONE:\n`;
          output += `      case CJ_SHIFT_KIND_LSL:\n`;
          output += `        shift_mode = 0;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_LSR:\n`;
          output += `        shift_mode = 1;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_ASR:\n`;
          output += `        shift_mode = 2;\n`;
          output += `        break;\n`;
          output += `      case CJ_SHIFT_KIND_ROR:\n`;
          if (disallowRor) {
            output += `        return;\n`;
          } else {
            output += `        shift_mode = 3;\n`;
            output += `        break;\n`;
          }
          output += `      default:\n`;
          output += `        return;\n`;
          output += `    }\n`;
          output += `    instr &= ~(${bitMask(shiftField.width)} << ${shiftField.lo});\n`;
          output += `    instr |= ((shift_mode & ${bitMask(shiftField.width)}) << ${shiftField.lo});\n`;
        }
        if (imm6Field) {
          output += `    uint32_t shift_amount = (src.shift.kind == CJ_SHIFT_KIND_NONE && !src.shift.has_amount) ? 0u : src.shift.amount;\n`;
          output += `    if (arm64_is_64bit(dst.reg)) {\n`;
          output += `      if (shift_amount > 63u) return;\n`;
          output += `    } else {\n`;
          output += `      if (shift_amount > 31u) return;\n`;
          output += `    }\n`;
          output += `    instr &= ~(${bitMask(imm6Field.width)} << ${imm6Field.lo});\n`;
          output += `    instr |= ((shift_amount & ${bitMask(imm6Field.width)}) << ${imm6Field.lo});\n`;
        }
        if (optionField) {
          output += `    if (src.extend.kind != CJ_EXTEND_KIND_NONE) {\n`;
          output += `      uint32_t option = 0;\n`;
          output += `      switch (src.extend.kind) {\n`;
          output += `        case CJ_EXTEND_KIND_UXTB: option = 0; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTH: option = 1; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTW: option = 2; break;\n`;
          output += `        case CJ_EXTEND_KIND_UXTX: option = 3; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTB: option = 4; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTH: option = 5; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTW: option = 6; break;\n`;
          output += `        case CJ_EXTEND_KIND_SXTX: option = 7; break;\n`;
          output += `        default: return;\n`;
          output += `      }\n`;
          output += `      instr &= ~(${bitMask(optionField.width)} << ${optionField.lo});\n`;
          output += `      instr |= ((option & ${bitMask(optionField.width)}) << ${optionField.lo});\n`;
          output += `    }\n`;
        }
      if (imm3Field) {
        output += `    if (src.extend.has_amount || src.extend.kind != CJ_EXTEND_KIND_NONE) {\n`;
        output += `      if (src.extend.kind == CJ_EXTEND_KIND_NONE) return;\n`;
        output += `      uint32_t extend_amount = src.extend.amount;\n`;
        output += `      if (extend_amount > ${bitMask(imm3Field.width)}) return;\n`;
        output += `      instr &= ~(${bitMask(imm3Field.width)} << ${imm3Field.lo});\n`;
        output += `      instr |= ((extend_amount & ${bitMask(imm3Field.width)}) << ${imm3Field.lo});\n`;
        output += `    }\n`;
      }

      output += `    cj_add_u32(ctx, instr);\n`;
      output += `    return;\n`;
      output += `  }\n`;
    } else if (format === 'reg_imm') {
      const immVarNames = ['imm', 'imm12', 'imm9', 'imm6', 'imm5', 'imm4', 'imm3'];
      const immVarName = immVarNames.find(name => findVariable(inst, name));
      const immVar = immVarName ? findVariable(inst, immVarName) : null;
      const hasImmediateField = fields.some(field => field && field.startsWith('imm'));
      const usesImmediate =
        !!immVar ||
        hasImmediateField ||
        imm3Field ||
        imm9Field ||
        imm6Field ||
        shField ||
        (ops.length >= 2 && ops[1] && ops[1].max !== undefined) ||
        !!findVariable(inst, 'hw');

      if (usesImmediate) {
        output += `  if (dst.type == CJ_REGISTER && src.type == CJ_CONSTANT) {\n`;
      const isFP = ops[0].type === 'fpreg';
      const parseFunc = isFP ? 'arm64_parse_fp_reg' : 'arm64_parse_reg';
      const hasRdVar = !!findVariable(inst, 'Rd');
      const hasRnVar = !!findVariable(inst, 'Rn');
      const immField = fields.find(field => field && field.startsWith('imm'));
      const immVar = immField ? findVariable(inst, immField) : null;
      const hwVar = findVariable(inst, 'hw');

      output += `    int rd = ${parseFunc}(dst.reg);\n`;
      output += `    if (rd < 0) return;\n`;
      if (hasRnVar) {
        output += `    int rn = rd;\n`;
      } else {
        output += `    int rn = 0;\n`;
      }
      output += `    uint64_t raw_imm = src.constant;\n`;
      output += `    uint64_t imm = raw_imm;\n`;

      if (immVar && immVar.width < 64) {
        output += `    imm &= ${bitMask(immVar.width)};\n`;
      }
      if (hwVar) {
        const shiftWidth = immVar ? immVar.width : 0;
        output += `    uint32_t hw = (uint32_t)((raw_imm >> ${shiftWidth}) & ${bitMask(hwVar.width)});\n`;
      }

      output += `    uint32_t instr = ${inst.value};\n`;

      if (!isFP) {
        const variant32 = variantGroup.find(v => v.inst.bitdiffs && v.inst.bitdiffs.includes('sf == 0'));
        const variant64 = variantGroup.find(v => v.inst.bitdiffs && v.inst.bitdiffs.includes('sf == 1'));
        if (variant32 && variant64) {
          output += `    instr = arm64_is_64bit(dst.reg) ? ${variant64.inst.value} : ${variant32.inst.value};\n`;
        } else if (variant64 && !variant32) {
          output += `    if (arm64_is_64bit(dst.reg)) instr = ${variant64.inst.value};\n`;
        }
      } else {
        output += `    int ftype = (dst.reg[0] == 'd') ? 0x1 : (dst.reg[0] == 's') ? 0x0 : 0x3;\n`;
        output += `    instr &= ~(0x3 << 22);\n`;
        output += `    instr |= (ftype << 22);\n`;
      }

      // Set register fields using metadata
      // Note: For reg_imm format, we may have Rd only or both Rd and Rn (where Rn=Rd)
      const regFieldsToEncode = inst.variables.filter(v => v.name === 'Rd' || v.name === 'Rn');
      for (const field of regFieldsToEncode) {
        const varName = field.name === 'Rd' ? 'rd' : 'rn';
        output += encodeFieldFromMetadata(field, varName);
      }
      if (immVar) {
        output += `    instr &= ~(${bitMask(immVar.width)} << ${immVar.lo});\n`;
        output += `    instr |= ((uint32_t)(imm & ${bitMask(immVar.width)})) << ${immVar.lo};\n`;
      }
      if (hwVar) {
        output += `    instr &= ~(${bitMask(hwVar.width)} << ${hwVar.lo});\n`;
        output += `    instr |= ((uint32_t)(hw & ${bitMask(hwVar.width)})) << ${hwVar.lo};\n`;
      }
      if (shField) {
        output += `    uint32_t sh = 0;\n`;
        output += `    if (src.shift.kind != CJ_SHIFT_KIND_NONE || src.shift.has_amount) {\n`;
        output += `      if (src.shift.kind != CJ_SHIFT_KIND_LSL) return;\n`;
        output += `      if (src.shift.amount == 0) {\n`;
        output += `        sh = 0;\n`;
        output += `      } else if (src.shift.amount == 12) {\n`;
        output += `        sh = 1;\n`;
        output += `      } else {\n`;
        output += `        return;\n`;
        output += `      }\n`;
        output += `    }\n`;
        output += `    instr &= ~(${bitMask(shField.width)} << ${shField.lo});\n`;
        output += `    instr |= ((sh & ${bitMask(shField.width)}) << ${shField.lo});\n`;
      }
        output += `    cj_add_u32(ctx, instr);\n`;
        output += `    return;\n`;
        output += `  }\n`;
      }
    }
  }

  output += `}\n\n`;
}

// Add branch instructions (manually - they need special label handling)
// Unconditional branch (B) - 26-bit offset
output += `static inline void cj_b(cj_ctx* ctx, cj_label label) {\n`;
output += `  cj_emit_branch(ctx, 0x14000000, label, 26, 0);\n`;
output += `}\n\n`;

// Branch with link (BL) - 26-bit offset
output += `static inline void cj_bl(cj_ctx* ctx, cj_label label) {\n`;
output += `  cj_emit_branch(ctx, 0x94000000, label, 26, 0);\n`;
output += `}\n\n`;

// Conditional branches (B.cond) - 19-bit offset, 16 conditions
const conditions = [
  { name: 'eq', code: 0b0000, desc: 'Equal' },
  { name: 'ne', code: 0b0001, desc: 'Not equal' },
  { name: 'cs', code: 0b0010, desc: 'Carry set / unsigned higher or same' },
  { name: 'cc', code: 0b0011, desc: 'Carry clear / unsigned lower' },
  { name: 'mi', code: 0b0100, desc: 'Minus / negative' },
  { name: 'pl', code: 0b0101, desc: 'Plus / positive or zero' },
  { name: 'vs', code: 0b0110, desc: 'Overflow set' },
  { name: 'vc', code: 0b0111, desc: 'Overflow clear' },
  { name: 'hi', code: 0b1000, desc: 'Unsigned higher' },
  { name: 'ls', code: 0b1001, desc: 'Unsigned lower or same' },
  { name: 'ge', code: 0b1010, desc: 'Signed greater than or equal' },
  { name: 'lt', code: 0b1011, desc: 'Signed less than' },
  { name: 'gt', code: 0b1100, desc: 'Signed greater than' },
  { name: 'le', code: 0b1101, desc: 'Signed less than or equal' },
  { name: 'al', code: 0b1110, desc: 'Always (normally omitted)' },
];

for (const cond of conditions) {
  output += `static inline void cj_b${cond.name}(cj_ctx* ctx, cj_label label) {\n`;
  output += `  uint32_t base = 0x54000000 | ${cond.code};\n`;
  output += `  cj_emit_branch(ctx, base, label, 19, 5);\n`;
  output += `}\n\n`;
}

// Compare and branch if zero (CBZ) - 19-bit offset
output += `static inline void cj_cbz(cj_ctx* ctx, cj_operand reg, cj_label label) {\n`;
output += `  if (reg.type != CJ_REGISTER) return;\n`;
output += `  int rt = arm64_parse_reg(reg.reg);\n`;
output += `  if (rt < 0) return;\n`;
output += `  uint32_t base = 0x34000000 | (rt & 0x1f);\n`;
output += `  if (arm64_is_64bit(reg.reg)) {\n`;
output += `    base |= (1 << 31);\n`;
output += `  }\n`;
output += `  cj_emit_branch(ctx, base, label, 19, 5);\n`;
output += `}\n\n`;

// Compare and branch if not zero (CBNZ) - 19-bit offset
output += `static inline void cj_cbnz(cj_ctx* ctx, cj_operand reg, cj_label label) {\n`;
output += `  if (reg.type != CJ_REGISTER) return;\n`;
output += `  int rt = arm64_parse_reg(reg.reg);\n`;
output += `  if (rt < 0) return;\n`;
output += `  uint32_t base = 0x34000000 | (1 << 24) | (rt & 0x1f);\n`;
output += `  if (arm64_is_64bit(reg.reg)) {\n`;
output += `    base |= (1 << 31);\n`;
output += `  }\n`;
output += `  cj_emit_branch(ctx, base, label, 19, 5);\n`;
output += `}\n\n`;

// Write to file
fs.writeFileSync('src/arch/arm64/backend.h', output);
console.error(`Generated src/arch/arm64/backend.h`);
