# changelog

all notable changes to this project will be documented in this file.

## [0.3.0] - 2025-10-22

- added `minilang` example
- expanded builder helpers with scratch-register stacks, call/return helpers, link-register preservation, and label resolution utilities
- added regression coverage for new builder call flows
- corrected arm64 branch fixup offsets so label-driven jumps land at the intended targets

## [0.2.0] - 2025-10-21

- introduced the builder helper layer for fn prologues, loops, and conditionals
- added documentation (`docs/builder.md`) and high-level fibonacci example demonstrating the new api
- added builder harness for ci
- added clang-format and clang-tidy to ci

## [0.1.0] - 2025-10-20

- initial public snapshot of `cj`
- auto-generated instruction encoders via `codegen/`
- core runtime (`ctx.c`), operand utilities (`op.h`), and register definitions
