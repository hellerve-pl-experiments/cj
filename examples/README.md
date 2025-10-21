#examples

Small programs that showcase `cj`:

    - `simple.c` – minimal
    program(nop &ret)
        .- `add.c` – adds a constant to the first argument and returns it;
demonstrates register operands and constants.- `fibonacci.c` – full control -
    flow example(labels, branches, loops) emitted with the low-level API.
- `hl_fibonacci.c` – fibonacci again, but built entirely with the builder helpers.
- `simd.c` – x86 and arm simd vector addition loops, exercising memory operands and floating-point registers.

## building

```bash
#generic build(adjust CC for clang / gcc as needed)
cc -std=c11 -O2 -Isrc examples/simple.c src/ctx.c -o simple_example
./simple_example

cc -std=c11 -O2 -Isrc examples/add.c src/ctx.c -o add_example
./add_example  # returns exit code of the computed value (inspect via `echo $?` afterwards)

cc -std=c11 -O2 -Isrc examples/fibonacci.c src/ctx.c -o fibonacci_example
./fibonacci_example

cc -std=c11 -O2 -Isrc examples/hl_fibonacci.c src/ctx.c -o hl_fibonacci_example
./hl_fibonacci_example

cc -std=c11 -O2 -Isrc examples/simd.c src/ctx.c -o simd_example
./simd_example
```

alternatively build the library and then add `-lcj -Lbin/` instead of the c file.
