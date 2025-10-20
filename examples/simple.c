#include "ctx.h"
#include "op.h"

int main() {
  cj_ctx* cj = create_cj_ctx();

#ifdef __aarch64__
  // ARM64: NOP and RET
  cj_nop(cj);
  cj_ret(cj);
#else
  // x86-64: NOP and RET
  cj_nop(cj);
  cj_ret(cj);
#endif

  cj_fn f = create_cj_fn(cj);

  f();

  destroy_cj_fn(cj, f);
  destroy_cj_ctx(cj);

  return 0;
}
