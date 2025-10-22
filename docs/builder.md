# builder api

the builder layer is a thin set of helpers on top of the raw emitted
instructions. it keeps control in your hands while removing the boilerplate
around abi registers, stack setup, and label plumbing, and it looks less scary.

## setup

- `cj_builder_fn_prologue(cj, stack_bytes, &frame)`: create a frame and reserve
  optional stack space (aligned for both arches).
- `cj_builder_fn_prologue_with_link_save(cj, stack_bytes, &frame)`: like above,
  but on ARM64 it also saves/restores `x30` for non-leaf functions.
- `cj_builder_fn_epilogue(cj, &frame)` / `cj_builder_return(cj, &frame)`:
  restore the frame and emit `ret`.

## operands

- `cj_builder_arg_int(cj, index)`: returns the platform-specific argument
  register.
- `cj_builder_scratch_reg(index)`: picks a caller-saved temporary.
- `cj_builder_scratch_init`, `cj_builder_scratch_acquire`,
  `cj_builder_scratch_release`: managed stack of scratch registers for balanced
  temporaries.
- `cj_builder_zero_operand()` + `cj_builder_clear(cj, dst)`: easy zeroing.
- `cj_builder_assign`, `cj_builder_add_assign`, `cj_builder_sub_assign`:
  assignment sugar.
- `cj_builder_call(ctx, scratch, label, args, count)`: loads integer argument
  registers (up to the ABI limit), emits the proper call/bl, and optionally
  preserves the return value via the scratch stack.
- `cj_builder_call_unary(ctx, scratch, label, arg)`: loads the first argument
  register, emits the right call/bl, and—when a scratch stack is supplied—moves
  the return value into a fresh scratch slot.
- `cj_resolve_label(ctx, module, label)`: convert a recorded label to a
  callable pointer after finalization.

## control flow

- `cj_builder_if`, `cj_builder_else`, `cj_builder_endif`: structured
  conditionals using `cj_condition`.
- `cj_builder_loop_begin`, `loop_condition`, `loop_continue`, `loop_break`,
  `loop_end`: generic loops.
- `cj_builder_for_begin` / `cj_builder_for_end` (+ optional `for_continue`,
  `for_break`): counting loops, pass counter, start, limit, step, and the exit
  condition.

## tiny example

```c
cj_ctx* cj = create_cj_ctx();
cj_builder_frame frame;
cj_builder_fn_prologue(cj, 0, &frame);

cj_operand sum = cj_builder_scratch_reg(0);
cj_builder_assign(cj, sum, cj_builder_zero_operand());

cj_operand i = cj_builder_scratch_reg(1);
cj_builder_for_loop loop = cj_builder_for_begin(
    cj,
    i,
    cj_make_constant(1),
    cj_builder_arg_int(cj, 0),
    cj_make_constant(1),
    CJ_COND_GE);

cj_builder_add_assign(cj, sum, i);
cj_builder_for_end(cj, &loop);

cj_builder_return_value(cj, &frame, sum);
```

see `examples/hl_fibonacci.c` for a longer walk-through that mixes assignments, loops, and conditionals.
