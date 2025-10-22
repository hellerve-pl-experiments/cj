// minimal s-expression jit example for cj

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <ptrauth.h>
#endif
#include "builder.h"
#define MAX_FUN 16
#define MAX_NODES 256

typedef enum
{
  NODE_NUM,
  NODE_PARAM,
  NODE_ADD,
  NODE_SUB,
  NODE_CALL
} node_kind;
typedef struct node node;
struct node
{
  node_kind kind;
  int value;
  int target;
  char name[32];
  node *left;
  node *right;
  node *arg;
};

typedef struct
{
  node nodes[MAX_NODES];
  int count;
} node_arena;
static node *arena_new(node_arena *arena)
{
  if (arena->count >= MAX_NODES)
  {
    fprintf(stderr, "node arena overflow\n");
    exit(1);
  }
  node *n = &arena->nodes[arena->count++];
  memset(n, 0, sizeof(*n));
  n->target = -1;
  return n;
}

typedef enum
{
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_IDENT,
  TOK_NUMBER,
  TOK_END
} token_kind;
typedef struct
{
  token_kind kind;
  char text[32];
  int value;
} token;
typedef struct
{
  const char *cur;
  token tok;
} lexer;

static void next_token(lexer *lx)
{
  while (*lx->cur && isspace((unsigned char)*lx->cur))
    lx->cur++;
  char c = *lx->cur;
  if (!c)
  {
    lx->tok.kind = TOK_END;
    return;
  }
  if (c == '(')
  {
    lx->tok.kind = TOK_LPAREN;
    lx->cur++;
    return;
  }
  if (c == ')')
  {
    lx->tok.kind = TOK_RPAREN;
    lx->cur++;
    return;
  }
  if (isdigit((unsigned char)c) || (c == '-' && isdigit((unsigned char)lx->cur[1])))
  {
    char *end = NULL;
    long val = strtol(lx->cur, &end, 10);
    lx->tok.kind = TOK_NUMBER;
    lx->tok.value = (int)val;
    size_t len = (size_t)(end - lx->cur);
    if (len >= sizeof(lx->tok.text))
      len = sizeof(lx->tok.text) - 1;
    memcpy(lx->tok.text, lx->cur, len);
    lx->tok.text[len] = '\0';
    lx->cur = end;
    return;
  }
  if (isalpha((unsigned char)c))
  {
    const char *start = lx->cur;
    while (*lx->cur && (isalnum((unsigned char)*lx->cur) || *lx->cur == '_'))
      lx->cur++;
    size_t len = (size_t)(lx->cur - start);
    if (len >= sizeof(lx->tok.text))
      len = sizeof(lx->tok.text) - 1;
    memcpy(lx->tok.text, start, len);
    lx->tok.text[len] = '\0';
    lx->tok.kind = TOK_IDENT;
    return;
  }
  fprintf(stderr, "unexpected character '%c'\n", c);
  exit(1);
}

static void init_lexer(lexer *lx, const char *src)
{
  lx->cur = src;
  next_token(lx);
}

static void expect(lexer *lx, token_kind kind)
{
  if (lx->tok.kind != kind)
  {
    fprintf(stderr, "parse error: unexpected token\n");
    exit(1);
  }
  next_token(lx);
}

static node *parse_expr(lexer *lx, node_arena *arena, const char *param);

typedef struct
{
  char name[32];
  char param[32];
  node *body;
  cj_label entry;
  size_t offset;
  int (*fn)(int);
} function;
static node *parse_expr(lexer *lx, node_arena *arena, const char *param)
{
  if (lx->tok.kind == TOK_NUMBER)
  {
    node *n = arena_new(arena);
    n->kind = NODE_NUM;
    n->value = lx->tok.value;
    next_token(lx);
    return n;
  }
  if (lx->tok.kind == TOK_IDENT)
  {
    if (strcmp(lx->tok.text, param) != 0)
    {
      fprintf(stderr, "unknown identifier '%s'\n", lx->tok.text);
      exit(1);
    }
    node *n = arena_new(arena);
    n->kind = NODE_PARAM;
    next_token(lx);
    return n;
  }
  if (lx->tok.kind != TOK_LPAREN)
  {
    fprintf(stderr, "expected expression\n");
    exit(1);
  }
  expect(lx, TOK_LPAREN);
  if (lx->tok.kind != TOK_IDENT)
  {
    fprintf(stderr, "expected operator\n");
    exit(1);
  }
  char op[32];
  strncpy(op, lx->tok.text, sizeof(op));
  op[sizeof(op) - 1] = '\0';
  next_token(lx);
  node *n = arena_new(arena);
  if (strcmp(op, "add") == 0)
  {
    n->kind = NODE_ADD;
    n->left = parse_expr(lx, arena, param);
    n->right = parse_expr(lx, arena, param);
    expect(lx, TOK_RPAREN);
    return n;
  }
  if (strcmp(op, "sub") == 0)
  {
    n->kind = NODE_SUB;
    n->left = parse_expr(lx, arena, param);
    n->right = parse_expr(lx, arena, param);
    expect(lx, TOK_RPAREN);
    return n;
  }
  if (strcmp(op, "call") == 0)
  {
    if (lx->tok.kind != TOK_IDENT)
    {
      fprintf(stderr, "expected function name after call\n");
      exit(1);
    }
    n->kind = NODE_CALL;
    strncpy(n->name, lx->tok.text, sizeof(n->name));
    n->name[sizeof(n->name) - 1] = '\0';
    next_token(lx);
    n->arg = parse_expr(lx, arena, param);
    expect(lx, TOK_RPAREN);
    return n;
  }
  fprintf(stderr, "unknown operator '%s'\n", op);
  exit(1);
}

static function parse_function(lexer *lx, node_arena *arena)
{
  function fn;
  memset(&fn, 0, sizeof(fn));
  expect(lx, TOK_LPAREN);
  if (lx->tok.kind != TOK_IDENT || strcmp(lx->tok.text, "def") != 0)
  {
    fprintf(stderr, "expected def\n");
    exit(1);
  }
  next_token(lx);
  if (lx->tok.kind != TOK_IDENT)
  {
    fprintf(stderr, "expected function name\n");
    exit(1);
  }
  strncpy(fn.name, lx->tok.text, sizeof(fn.name));
  fn.name[sizeof(fn.name) - 1] = '\0';
  next_token(lx);
  expect(lx, TOK_LPAREN);
  if (lx->tok.kind != TOK_IDENT)
  {
    fprintf(stderr, "expected parameter name\n");
    exit(1);
  }
  strncpy(fn.param, lx->tok.text, sizeof(fn.param));
  fn.param[sizeof(fn.param) - 1] = '\0';
  next_token(lx);
  expect(lx, TOK_RPAREN);
  fn.body = parse_expr(lx, arena, fn.param);
  expect(lx, TOK_RPAREN);
  return fn;
}

static int find_function(function *fns, int count, const char *name)
{
  for (int i = 0; i < count; i++)
  {
    if (strcmp(fns[i].name, name) == 0)
      return i;
  }
  return -1;
}

static void resolve_calls(node_arena *arena, function *fns, int count)
{
  for (int i = 0; i < arena->count; i++)
  {
    node *n = &arena->nodes[i];
    if (n->kind == NODE_CALL)
    {
      int idx = find_function(fns, count, n->name);
      if (idx < 0)
      {
        fprintf(stderr, "unknown function '%s'\n", n->name);
        exit(1);
      }
      n->target = idx;
    }
  }
}

typedef struct
{
  cj_ctx *cj;
  function *functions;
  int scratch_depth;
} codegen;

static cj_operand acquire_scratch(codegen *cg)
{
  if (cg->scratch_depth >= 6)
  {
    fprintf(stderr, "scratch register exhausted\n");
    exit(1);
  }
  int idx = cg->scratch_depth++;
  return cj_builder_scratch_reg((unsigned)idx);
}

static void release_scratch(codegen *cg)
{
  if (cg->scratch_depth <= 0)
  {
    fprintf(stderr, "release underflow\n");
    exit(1);
  }
  cg->scratch_depth--;
}

static cj_operand emit_expr(codegen *cg, node *n)
{
  switch (n->kind)
  {
  case NODE_NUM:
  {
    cj_operand dst = acquire_scratch(cg);
    cj_builder_assign(cg->cj, dst, cj_make_constant((uint64_t)(uint32_t)n->value));
    return dst;
  }
  case NODE_PARAM:
  {
    cj_operand dst = acquire_scratch(cg);
    cj_builder_assign(cg->cj, dst, cj_builder_arg_int(cg->cj, 0));
    return dst;
  }
  case NODE_ADD:
  case NODE_SUB:
  {
    cj_operand lhs = emit_expr(cg, n->left);
    cj_operand rhs = emit_expr(cg, n->right);
    if (n->kind == NODE_ADD)
      cj_add(cg->cj, lhs, rhs);
    else
      cj_sub(cg->cj, lhs, rhs);
    release_scratch(cg);
    return lhs;
  }
  case NODE_CALL:
  {
    cj_operand arg = emit_expr(cg, n->arg);
    cj_builder_assign(cg->cj, cj_builder_arg_int(cg->cj, 0), arg);
    release_scratch(cg);
#if defined(__aarch64__) || defined(_M_ARM64)
    cj_bl(cg->cj, cg->functions[n->target].entry);
#else
    cj_call(cg->cj, cg->functions[n->target].entry);
#endif
    cj_operand dst = acquire_scratch(cg);
    cj_builder_assign(cg->cj, dst, cj_builder_return_reg());
    return dst;
  }
  }
  fprintf(stderr, "unsupported node kind\n");
  exit(1);
}

static void emit_function(codegen *cg, function *fn)
{
  cg->scratch_depth = 0;
  cj_mark_label(cg->cj, fn->entry);
#if defined(__aarch64__) || defined(_M_ARM64)
  cj_operand sp = cj_make_register("sp");
  cj_sub(cg->cj, sp, cj_make_constant(16));
  cj_str(cg->cj, cj_make_register("x30"), cj_make_memory("sp", NULL, 1, 0));
  cj_operand result = emit_expr(cg, fn->body);
  if (!(result.type == CJ_REGISTER && result.reg && strcmp(result.reg, "w0") == 0))
  {
    cj_mov(cg->cj, cj_make_register("w0"), result);
  }
  cj_ldr(cg->cj, cj_make_register("x30"), cj_make_memory("sp", NULL, 1, 0));
  cj_add(cg->cj, sp, cj_make_constant(16));
  cj_ret(cg->cj);
#else
  cj_builder_frame frame;
  cj_builder_fn_prologue(cg->cj, 0, &frame);
  cj_operand result = emit_expr(cg, fn->body);
  cj_builder_return_value(cg->cj, &frame, result);
#endif
  release_scratch(cg);
}

static const char *program_source = "(def main (x) (sub (call inc x) 3))\n"
                                    "(def inc (x) (add x 1))\n";

int main(void)
{
  node_arena arena = {0};
  function functions[MAX_FUN];
  int function_count = 0;
  lexer lx;
  init_lexer(&lx, program_source);

  while (lx.tok.kind != TOK_END)
  {
    if (function_count >= MAX_FUN)
    {
      fprintf(stderr, "too many functions\n");
      return 1;
    }
    functions[function_count++] = parse_function(&lx, &arena);
  }

  int main_idx = find_function(functions, function_count, "main");
  if (main_idx < 0)
  {
    fprintf(stderr, "no main function\n");
    return 1;
  }
  if (main_idx != 0)
  {
    function tmp = functions[0];
    functions[0] = functions[main_idx];
    functions[main_idx] = tmp;
    main_idx = 0;
  }

  resolve_calls(&arena, functions, function_count);

  cj_ctx *cj = create_cj_ctx();
  for (int i = 0; i < function_count; i++)
    functions[i].entry = cj_create_label(cj);

  codegen cg = {.cj = cj, .functions = functions, .scratch_depth = 0};
  emit_function(&cg, &functions[main_idx]);
  for (int i = 0; i < function_count; i++)
    if (i != main_idx)
      emit_function(&cg, &functions[i]);

  cj_fn module = create_cj_fn(cj);
  if (!module)
  {
    fprintf(stderr, "failed to finalize jit module\n");
    destroy_cj_ctx(cj);
    return 1;
  }

  for (int i = 0; i < function_count; ++i)
  {
    size_t offset = cj->label_positions[functions[i].entry.id];
    functions[i].fn = (int (*)(int))((uint8_t *)(void *)module + offset);
  }

  printf("minilang demo:\n");
  for (int i = 0; i <= 5; i++)
  {
    int result = functions[main_idx].fn(i);
    printf("  main(%d) = %d\n", i, result);
  }

  destroy_cj_fn(cj, module);
  destroy_cj_ctx(cj);
  return 0;
}
