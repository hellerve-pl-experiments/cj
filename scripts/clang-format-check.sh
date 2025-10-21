#!/usr/bin/env bash
set -euo pipefail

# Identify tracked C sources and headers that should be checked by clang-format.
files=$(git ls-files '*.c' '*.h' \
  ':(exclude)src/arch/**' \
  ':(exclude)jit_tests_arm64/**' \
  ':(exclude)bin/**' \
  ':(exclude)node_modules/**')

if [ -z "$files" ]; then
  exit 0
fi

clang-format --style=file --dry-run --Werror $files
