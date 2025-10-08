#pragma once

#include "../../op.h"

// x86-64 general, floating-point, vector, mask, and control registers.
// These are exposed as `cj_<name>` operands via the CJ_REG macro.

CJ_REG(rip);   /* RIP register.*/
CJ_REG(es);    /* CS segment register.*/
CJ_REG(cs);    /* SS segment register.*/
CJ_REG(ss);    /* DS segment register.*/
CJ_REG(ds);    /* ES segment register.*/
CJ_REG(fs);    /* FS segment register.*/
CJ_REG(gs);    /* GS segment register.*/

CJ_REG(al);   /* 8-bit low GPB register.*/
CJ_REG(cl);   /* 8-bit low GPB register.*/
CJ_REG(dl);   /* 8-bit low GPB register.*/
CJ_REG(bl);   /* 8-bit low GPB register.*/
CJ_REG(spl);  /* 8-bit low GPB register (X64).*/
CJ_REG(bpl);  /* 8-bit low GPB register (X64).*/
CJ_REG(sil);  /* 8-bit low GPB register (X64).*/
CJ_REG(dil);  /* 8-bit low GPB register (X64).*/
CJ_REG(r8b);  /* 8-bit low GPB register (X64).*/
CJ_REG(r9b);  /* 8-bit low GPB register (X64).*/
CJ_REG(r10b); /* 8-bit low GPB register (X64).*/
CJ_REG(r11b); /* 8-bit low GPB register (X64).*/
CJ_REG(r12b); /* 8-bit low GPB register (X64).*/
CJ_REG(r13b); /* 8-bit low GPB register (X64).*/
CJ_REG(r14b); /* 8-bit low GPB register (X64).*/
CJ_REG(r15b); /* 8-bit low GPB register (X64).*/

CJ_REG(ah);  /* 8-bit high GPB register.*/
CJ_REG(ch);  /* 8-bit high GPB register.*/
CJ_REG(dh);  /* 8-bit high GPB register.*/
CJ_REG(bh);  /* 8-bit high GPB register.*/

CJ_REG(ax);    /* 16-bit GPW register.*/
CJ_REG(cx);    /* 16-bit GPW register.*/
CJ_REG(dx);    /* 16-bit GPW register.*/
CJ_REG(bx);    /* 16-bit GPW register.*/
CJ_REG(sp);    /* 16-bit GPW register.*/
CJ_REG(bp);    /* 16-bit GPW register.*/
CJ_REG(si);    /* 16-bit GPW register.*/
CJ_REG(di);    /* 16-bit GPW register.*/
CJ_REG(r8w);    /* 16-bit GPW register (X64).*/
CJ_REG(r9w);    /* 16-bit GPW register (X64).*/
CJ_REG(r10w);   /* 16-bit GPW register (X64).*/
CJ_REG(r11w);   /* 16-bit GPW register (X64).*/
CJ_REG(r12w);   /* 16-bit GPW register (X64).*/
CJ_REG(r13w);   /* 16-bit GPW register (X64).*/
CJ_REG(r14w);   /* 16-bit GPW register (X64).*/
CJ_REG(r15w);   /* 16-bit GPW register (X64).*/

CJ_REG(eax);    /* 32-bit GPD register.*/
CJ_REG(ecx);    /* 32-bit GPD register.*/
CJ_REG(edx);    /* 32-bit GPD register.*/
CJ_REG(ebx);    /* 32-bit GPD register.*/
CJ_REG(esp);    /* 32-bit GPD register.*/
CJ_REG(ebp);    /* 32-bit GPD register.*/
CJ_REG(esi);    /* 32-bit GPD register.*/
CJ_REG(edi);    /* 32-bit GPD register.*/
CJ_REG(r8d);    /* 32-bit GPD register (X64).*/
CJ_REG(r9d);    /* 32-bit GPD register (X64).*/
CJ_REG(r10d);   /* 32-bit GPD register (X64).*/
CJ_REG(r11d);   /* 32-bit GPD register (X64).*/
CJ_REG(r12d);   /* 32-bit GPD register (X64).*/
CJ_REG(r13d);   /* 32-bit GPD register (X64).*/
CJ_REG(r14d);   /* 32-bit GPD register (X64).*/
CJ_REG(r15d);   /* 32-bit GPD register (X64).*/

CJ_REG(rax);    /* 64-bit GPQ register (X64).*/
CJ_REG(rcx);    /* 64-bit GPQ register (X64).*/
CJ_REG(rdx);    /* 64-bit GPQ register (X64).*/
CJ_REG(rbx);    /* 64-bit GPQ register (X64).*/
CJ_REG(rsp);    /* 64-bit GPQ register (X64).*/
CJ_REG(rbp);    /* 64-bit GPQ register (X64).*/
CJ_REG(rsi);    /* 64-bit GPQ register (X64).*/
CJ_REG(rdi);    /* 64-bit GPQ register (X64).*/
CJ_REG(r8);    /* 64-bit GPQ register (X64).*/
CJ_REG(r9);    /* 64-bit GPQ register (X64).*/
CJ_REG(r10);   /* 64-bit GPQ register (X64).*/
CJ_REG(r11);   /* 64-bit GPQ register (X64).*/
CJ_REG(r12);   /* 64-bit GPQ register (X64).*/
CJ_REG(r13);   /* 64-bit GPQ register (X64).*/
CJ_REG(r14);   /* 64-bit GPQ register (X64).*/
CJ_REG(r15);   /* 64-bit GPQ register (X64).*/

CJ_REG(fp0);     /* 80-bit FPU register.*/
CJ_REG(fp1);     /* 80-bit FPU register.*/
CJ_REG(fp2);     /* 80-bit FPU register.*/
CJ_REG(fp3);     /* 80-bit FPU register.*/
CJ_REG(fp4);     /* 80-bit FPU register.*/
CJ_REG(fp5);     /* 80-bit FPU register.*/
CJ_REG(fp6);     /* 80-bit FPU register.*/
CJ_REG(fp7);     /* 80-bit FPU register.*/

CJ_REG(mm0);     /* 64-bit MMX register.*/
CJ_REG(mm1);     /* 64-bit MMX register.*/
CJ_REG(mm2);     /* 64-bit MMX register.*/
CJ_REG(mm3);     /* 64-bit MMX register.*/
CJ_REG(mm4);     /* 64-bit MMX register.*/
CJ_REG(mm5);     /* 64-bit MMX register.*/
CJ_REG(mm6);     /* 64-bit MMX register.*/
CJ_REG(mm7);     /* 64-bit MMX register.*/

CJ_REG(k0);      /* 64-bit K register.*/
CJ_REG(k1);      /* 64-bit K register.*/
CJ_REG(k2);      /* 64-bit K register.*/
CJ_REG(k3);      /* 64-bit K register.*/
CJ_REG(k4);      /* 64-bit K register.*/
CJ_REG(k5);      /* 64-bit K register.*/
CJ_REG(k6);      /* 64-bit K register.*/
CJ_REG(k7);      /* 64-bit K register.*/

CJ_REG(xmm0);    /* 128-bit XMM register.*/
CJ_REG(xmm1);    /* 128-bit XMM register.*/
CJ_REG(xmm2);    /* 128-bit XMM register.*/
CJ_REG(xmm3);    /* 128-bit XMM register.*/
CJ_REG(xmm4);    /* 128-bit XMM register.*/
CJ_REG(xmm5);    /* 128-bit XMM register.*/
CJ_REG(xmm6);    /* 128-bit XMM register.*/
CJ_REG(xmm7);    /* 128-bit XMM register.*/
CJ_REG(xmm8);    /* 128-bit XMM register (X64).*/
CJ_REG(xmm9);    /* 128-bit XMM register (X64).*/
CJ_REG(xmm10);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm11);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm12);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm13);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm14);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm15);   /* 128-bit XMM register (X64).*/
CJ_REG(xmm16);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm17);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm18);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm19);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm20);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm21);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm22);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm23);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm24);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm25);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm26);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm27);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm28);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm29);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm30);   /* 128-bit XMM register (X64 & AVX512_VL+).*/
CJ_REG(xmm31);   /* 128-bit XMM register (X64 & AVX512_VL+).*/

CJ_REG(ymm0);    /* 256-bit YMM register.*/
CJ_REG(ymm1);    /* 256-bit YMM register.*/
CJ_REG(ymm2);    /* 256-bit YMM register.*/
CJ_REG(ymm3);    /* 256-bit YMM register.*/
CJ_REG(ymm4);    /* 256-bit YMM register.*/
CJ_REG(ymm5);    /* 256-bit YMM register.*/
CJ_REG(ymm6);    /* 256-bit YMM register.*/
CJ_REG(ymm7);    /* 256-bit YMM register.*/
CJ_REG(ymm8);    /* 256-bit YMM register (X64).*/
CJ_REG(ymm9);    /* 256-bit YMM register (X64).*/
CJ_REG(ymm10);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm11);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm12);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm13);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm14);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm15);   /* 256-bit YMM register (X64).*/
CJ_REG(ymm16);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm17);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm18);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm19);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm20);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm21);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm22);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm23);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm24);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm25);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm26);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm27);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm28);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm29);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm30);   /* 256-bit YMM register (X64 & AVX512_VL+).*/
CJ_REG(ymm31);   /* 256-bit YMM register (X64 & AVX512_VL+).*/

CJ_REG(zmm0);    /* 512-bit ZMM register.*/
CJ_REG(zmm1);    /* 512-bit ZMM register.*/
CJ_REG(zmm2);    /* 512-bit ZMM register.*/
CJ_REG(zmm3);    /* 512-bit ZMM register.*/
CJ_REG(zmm4);    /* 512-bit ZMM register.*/
CJ_REG(zmm5);    /* 512-bit ZMM register.*/
CJ_REG(zmm6);    /* 512-bit ZMM register.*/
CJ_REG(zmm7);    /* 512-bit ZMM register.*/
CJ_REG(zmm8);    /* 512-bit ZMM register (X64).*/
CJ_REG(zmm9);    /* 512-bit ZMM register (X64).*/
CJ_REG(zmm10);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm11);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm12);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm13);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm14);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm15);   /* 512-bit ZMM register (X64).*/
CJ_REG(zmm16);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm17);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm18);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm19);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm20);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm21);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm22);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm23);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm24);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm25);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm26);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm27);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm28);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm29);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm30);   /* 512-bit ZMM register (X64 & AVX512_F+).*/
CJ_REG(zmm31);   /* 512-bit ZMM register (X64 & AVX512_F+).*/

CJ_REG(bnd0);    /* 128-bit bound register.*/
CJ_REG(bnd1);    /* 128-bit bound register.*/
CJ_REG(bnd2);    /* 128-bit bound register.*/
CJ_REG(bnd3);    /* 128-bit bound register.*/

CJ_REG(cr0);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr1);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr2);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr3);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr4);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr5);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr6);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr7);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr8);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr9);     /* 32-bit or 64-bit control register.*/
CJ_REG(cr10);    /* 32-bit or 64-bit control register.*/
CJ_REG(cr11);    /* 32-bit or 64-bit control register.*/
CJ_REG(cr12);    /* 32-bit or 64-bit control register.*/
CJ_REG(cr13);    /* 32-bit or 64-bit control register.*/
CJ_REG(cr14);    /* 32-bit or 64-bit control register.*/
CJ_REG(cr15);    /* 32-bit or 64-bit control register.*/

CJ_REG(dr0);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr1);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr2);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr3);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr4);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr5);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr6);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr7);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr8);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr9);     /* 32-bit or 64-bit debug register.*/
CJ_REG(dr10);    /* 32-bit or 64-bit debug register.*/
CJ_REG(dr11);    /* 32-bit or 64-bit debug register.*/
CJ_REG(dr12);    /* 32-bit or 64-bit debug register.*/
CJ_REG(dr13);    /* 32-bit or 64-bit debug register.*/
CJ_REG(dr14);    /* 32-bit or 64-bit debug register.*/
CJ_REG(dr15);    /* 32-bit or 64-bit debug register.*/

#undef CJ_REG
