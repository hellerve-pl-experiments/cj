#pragma once

#include "op.h"

#if defined(__x86_64__) || defined(_M_X64)
#include "arch/x86_64/registers.h"
#elif defined(__aarch64__) || defined(_M_ARM64)
#include "arch/arm64/registers.h"
#else
#error "Unsupported architecture"
#endif

#undef CJ_REG
