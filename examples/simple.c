#include "register.h"
#include "op.h"

int main() {
  cj_ctx* cj = create_cj_ctx();
  cj_nop(cj);
  cj_ret(cj);

  cj_fn f = create_cj_fn(cj);

  f();

  destroy_cj_fn(cj, f);
  destroy_cj_ctx(cj);
}
