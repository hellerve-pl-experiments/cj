/*
 * Fibonacci - JIT Compilation Demo
 *
 * This example demonstrates JIT compilation of an iterative Fibonacci function.
 * We'll generate optimized machine code at runtime that computes Fibonacci numbers.
 *
 * Function: int fib(int n)
 *   Returns the nth Fibonacci number
 *   fib(n) = iterative calculation
 *
 * This shows:
 *   - Conditional branches with labels
 *   - Loops in JIT-compiled code
 *   - Register allocation patterns
 *   - ARM64 function calling conventions
 */

#include <stdio.h>
#include <time.h>
#include "ctx.h"
#include "op.h"

// Type for our JIT-compiled function
// int fib(int n)
typedef int (*fib_fn)(int);

// Reference implementation for comparison
int fib_c(int n) {
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

int main(void) {
    // Create JIT context
    cj_ctx* cj = create_cj_ctx();

    // Generate iterative Fibonacci:
    // int fib(int n) {
    //     if (n <= 1) return n;
    //     int a = 0, b = 1;
    //     for (int i = 2; i <= n; i++) {
    //         int temp = a + b;
    //         a = b;
    //         b = temp;
    //     }
    //     return b;
    // }
    //
    // ARM64 calling convention: w0 = n (32-bit int)
    // We'll use: w0 = n, w1 = a, w2 = b, w3 = temp, w4 = i

#ifdef __aarch64__
    cj_operand w0 = {.type = CJ_REGISTER, .reg = "w0"};  // n (and return value)
    cj_operand w1 = {.type = CJ_REGISTER, .reg = "w1"};  // a
    cj_operand w2 = {.type = CJ_REGISTER, .reg = "w2"};  // b
    cj_operand w3 = {.type = CJ_REGISTER, .reg = "w3"};  // temp
    cj_operand w4 = {.type = CJ_REGISTER, .reg = "w4"};  // i
    cj_operand wzr = {.type = CJ_REGISTER, .reg = "wzr"}; // zero register

    // Create labels
    cj_label return_n = cj_create_label(cj);
    cj_label loop_start = cj_create_label(cj);
    cj_label loop_end = cj_create_label(cj);

    // if (n <= 1) return n
    cj_operand one_imm = {.type = CJ_CONSTANT, .constant = 1};
    cj_cmp(cj, w0, one_imm);
    cj_ble(cj, return_n);  // branch if n <= 1

    // Initialize: a = 0, b = 1, i = 2
    cj_mov(cj, w1, wzr);              // a = 0
    cj_mov(cj, w2, wzr);              // b = 0
    cj_operand one_const = {.type = CJ_CONSTANT, .constant = 1};
    cj_add(cj, w2, one_const);        // b = 0 + 1 = 1
    cj_operand two_const = {.type = CJ_CONSTANT, .constant = 2};
    cj_mov(cj, w4, wzr);              // i = 0
    cj_add(cj, w4, two_const);        // i = 0 + 2 = 2

    // Loop: while (i <= n)
    cj_mark_label(cj, loop_start);

    //   temp = a + b
    cj_mov(cj, w3, w1);        // temp = a
    cj_add(cj, w3, w2);        // temp = a + b

    //   a = b
    cj_mov(cj, w1, w2);        // a = b

    //   b = temp
    cj_mov(cj, w2, w3);        // b = temp

    //   i++
    cj_add(cj, w4, one_const);  // i++

    //   if (i <= n) goto loop_start
    cj_cmp(cj, w4, w0);
    cj_ble(cj, loop_start);

    // return b
    cj_mov(cj, w0, w2);        // return value = b
    cj_ret(cj);

    // return_n: return n (already in w0)
    cj_mark_label(cj, return_n);
    cj_ret(cj);
#else
    // x86-64 version (32-bit integer operations)
    cj_operand edi = {.type = CJ_REGISTER, .reg = "edi"};  // n
    cj_operand eax = {.type = CJ_REGISTER, .reg = "eax"};  // a (and return value)
    cj_operand ecx = {.type = CJ_REGISTER, .reg = "ecx"};  // b
    cj_operand edx = {.type = CJ_REGISTER, .reg = "edx"};  // temp
    cj_operand esi = {.type = CJ_REGISTER, .reg = "esi"};  // i

    cj_operand zero = {.type = CJ_CONSTANT, .constant = 0};
    cj_operand one = {.type = CJ_CONSTANT, .constant = 1};
    cj_operand two = {.type = CJ_CONSTANT, .constant = 2};

    // Create labels
    cj_label return_n = cj_create_label(cj);
    cj_label loop_start = cj_create_label(cj);

    // if (n <= 1) return n
    cj_cmp(cj, edi, one);
    cj_jle(cj, return_n);

    // Initialize: a = 0, b = 1, i = 2
    cj_mov(cj, eax, zero);     // a = 0
    cj_mov(cj, ecx, one);      // b = 1
    cj_mov(cj, esi, two);      // i = 2

    // Loop: while (i <= n)
    cj_mark_label(cj, loop_start);

    //   temp = a + b
    cj_mov(cj, edx, eax);      // temp = a
    cj_add(cj, edx, ecx);      // temp += b

    //   a = b
    cj_mov(cj, eax, ecx);      // a = b

    //   b = temp
    cj_mov(cj, ecx, edx);      // b = temp

    //   i++
    cj_add(cj, esi, one);      // i++

    //   if (i <= n) goto loop_start
    cj_cmp(cj, esi, edi);
    cj_jle(cj, loop_start);

    // return b
    cj_mov(cj, eax, ecx);      // return value = b
    cj_ret(cj);

    // return_n: return n (already in edi)
    cj_mark_label(cj, return_n);
    cj_mov(cj, eax, edi);
    cj_ret(cj);
#endif

    // Create executable function
    fib_fn fib_jit = (fib_fn)create_cj_fn(cj);

    // Test the JIT-compiled function
    int all_pass = 1;
    for (int i = 0; i <= 15; i++) {
        int result = fib_jit(i);
        int expected = fib_c(i);
        int pass = (result == expected);
        all_pass = all_pass && pass;
        printf("fib(%d) = %d (expected: %d)\n", i, result, expected);
    }

    // Clean up
    destroy_cj_fn(cj, (cj_fn)fib_jit);
    destroy_cj_ctx(cj);

    return 0;
}
