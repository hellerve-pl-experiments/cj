#pragma once

#include "../../op.h"

// ARM64 general-purpose register operands exposed via CJ_REG.

// 64-bit general-purpose registers X0-X30.
CJ_REG(x0);
CJ_REG(x1);
CJ_REG(x2);
CJ_REG(x3);
CJ_REG(x4);
CJ_REG(x5);
CJ_REG(x6);
CJ_REG(x7);
CJ_REG(x8);
CJ_REG(x9);
CJ_REG(x10);
CJ_REG(x11);
CJ_REG(x12);
CJ_REG(x13);
CJ_REG(x14);
CJ_REG(x15);
CJ_REG(x16);
CJ_REG(x17);
CJ_REG(x18);
CJ_REG(x19);
CJ_REG(x20);
CJ_REG(x21);
CJ_REG(x22);
CJ_REG(x23);
CJ_REG(x24);
CJ_REG(x25);
CJ_REG(x26);
CJ_REG(x27);
CJ_REG(x28);
CJ_REG(x29);
CJ_REG(x30);

// 32-bit general-purpose registers W0-W30 (lower half of X registers).
CJ_REG(w0);
CJ_REG(w1);
CJ_REG(w2);
CJ_REG(w3);
CJ_REG(w4);
CJ_REG(w5);
CJ_REG(w6);
CJ_REG(w7);
CJ_REG(w8);
CJ_REG(w9);
CJ_REG(w10);
CJ_REG(w11);
CJ_REG(w12);
CJ_REG(w13);
CJ_REG(w14);
CJ_REG(w15);
CJ_REG(w16);
CJ_REG(w17);
CJ_REG(w18);
CJ_REG(w19);
CJ_REG(w20);
CJ_REG(w21);
CJ_REG(w22);
CJ_REG(w23);
CJ_REG(w24);
CJ_REG(w25);
CJ_REG(w26);
CJ_REG(w27);
CJ_REG(w28);
CJ_REG(w29);
CJ_REG(w30);

// Special registers.
CJ_REG(sp);
CJ_REG(xzr);
CJ_REG(wzr);

#undef CJ_REG
