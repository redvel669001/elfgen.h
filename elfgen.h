#ifndef ELFGEN_H_
#define ELFGEN_H_

#define DA_INIT_CAPACITY 1024

// Largely copied from the nob_da_append macro in nob.h, albeit highly simplified.
// https://github.com/tsoding/nob.h/blob/main/nob.h
#define da_append(da, item)                                             \
  do {                                                                  \
    if ((da)->capacity < (da)->count + 1) {                             \
      if ((da)->capacity == 0) {                                        \
        (da)->capacity = DA_INIT_CAPACITY;                              \
      }                                                                 \
      while ((da)->capacity < (da)->count + 1) {                        \
        (da)->capacity *= 2;                                            \
      }                                                                 \
      (da)->items = realloc((da)->items, (da)->capacity * sizeof(*(da)->items)); \
    }                                                                   \
    (da)->items[(da)->count++] = (item);                                \
  } while (0)

#define ELF_DEF static inline
#include <elf.h>
#include <stdbool.h>
/* #include <assert.h> */
#include <stdlib.h>
#include <string.h>

typedef enum {
  RAX,
  RBX,
  RCX,
  RDX,
  RSI,
  RDI,
  RBP,
  RSP,
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,
  
  EAX,
  EBX,
  ECX,
  EDX,
  ESI,
  EDI,
  EBP,
  ESP,
  R8D,
  R9D,
  R10D,
  R11D,
  R12D,
  R13D,
  R14D,
  R15D,

  AX,
  BX,
  CX,
  DX,
  SI,
  DI,
  BP,
  SP,
  R8W,
  R9W,
  R10W,
  R11W,
  R12W,
  R13W,
  R14W,
  R15W,

  AL,
  AH,
  BL,
  BH,
  CL,
  CH,
  DL,
  DH,
  SIL,
  DIL,
  BPL,
  SPL,
  R8B,
  R9B,
  R10B,
  R11B,
  R12B,
  R13B,
  R14B,
  R15B,
  
  REGISTERS,
} Register;

typedef struct {
  char *items;
  size_t count;
  size_t capacity;
} Bytes;

ELF_DEF void append_bytes(Bytes *s, const char *bytes, size_t len);
ELF_DEF void gen_little_endian(Bytes *s, size_t big_endian, size_t len);

/*
  1) `r` refers to register
  2) `imm` refers to immediate values
  3) `cl` refers to the the low 8 bits of the C register, because for
  some reason, that seems to be treated as something special.
 */

// ************************* ret etc *************************
ELF_DEF void gen_ret(Bytes *s);
ELF_DEF void gen_ret_imm(Bytes *s, size_t ret);

// ************************* jmp etc *************************
ELF_DEF void gen_jmp_imm_short_form(Bytes *s, char jmp);
ELF_DEF void gen_jmp_imm_long_form(Bytes *s, size_t jmp);

ELF_DEF void gen_je_imm_short_form(Bytes *s, char je);
ELF_DEF void gen_je_imm_long_form(Bytes *s, size_t je);

ELF_DEF void gen_jne_imm_short_form(Bytes *s, char jne);
ELF_DEF void gen_jne_imm_long_form(Bytes *s, size_t jne);

ELF_DEF void gen_jg_imm_short_form(Bytes *s, char jg);
ELF_DEF void gen_jg_imm_long_form(Bytes *s, size_t jg);

ELF_DEF void gen_jge_imm_short_form(Bytes *s, char jge);
ELF_DEF void gen_jge_imm_long_form(Bytes *s, size_t jge);

ELF_DEF void gen_jl_imm_short_form(Bytes *s, char jl);
ELF_DEF void gen_jl_imm_long_form(Bytes *s, size_t jl);

ELF_DEF void gen_jle_imm_short_form(Bytes *s, char jle);
ELF_DEF void gen_jle_imm_long_form(Bytes *s, size_t jle);

ELF_DEF void gen_call_imm_short_form(Bytes *s, char call);
ELF_DEF void gen_call_imm_long_form(Bytes *s, size_t call);

ELF_DEF void gen_push_imm_short_form(Bytes *s, char push);
ELF_DEF void gen_push_imm_long_form(Bytes *s, size_t push);

// ************************* 64-bits *************************
ELF_DEF void gen_add_64_r_imm_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_64_r_imm_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_64_r_imm_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_64_r_imm_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_64(Bytes *s, Register r);
ELF_DEF void gen_dec_64(Bytes *s, Register r);

ELF_DEF void gen_imul_64_r_imm_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_64_r_imm_long_form(Bytes *s, Register r, size_t mul);

ELF_DEF void gen_div_64(Bytes *s, Register r);

ELF_DEF void gen_and_64_r_imm_short_form(Bytes *s, Register r, char and);
ELF_DEF void gen_and_64_r_imm_long_form(Bytes *s, Register r, size_t and);

ELF_DEF void gen_or_64_r_imm_short_form(Bytes *s, Register r, char or);
ELF_DEF void gen_or_64_r_imm_long_form(Bytes *s, Register r, size_t or);

ELF_DEF void gen_not_64(Bytes *s, Register r);

ELF_DEF void gen_shr_64_r_1(Bytes *s, Register r);
ELF_DEF void gen_shr_64_r_imm(Bytes *s, Register r, char shr);
ELF_DEF void gen_shr_64_r_cl(Bytes *s, Register r);

ELF_DEF void gen_shl_64_r_1(Bytes *s, Register r);
ELF_DEF void gen_shl_64_r_imm(Bytes *s, Register r, char shl);
ELF_DEF void gen_shl_64_r_cl(Bytes *s, Register r);

ELF_DEF void gen_sar_64_r_1(Bytes *s, Register r);
ELF_DEF void gen_sar_64_r_imm(Bytes *s, Register r, char sar);
ELF_DEF void gen_sar_64_r_cl(Bytes *s, Register r);

ELF_DEF void gen_cmp_64_r_imm_short_form(Bytes *s, Register r, char cmp);
ELF_DEF void gen_cmp_64_r_imm_long_form(Bytes *s, Register r, size_t cmp);

ELF_DEF void gen_push_64(Bytes *s, Register r);
ELF_DEF void gen_pop_64(Bytes *s, Register r);

ELF_DEF void gen_jmp_r_64(Bytes *s, Register r);

ELF_DEF void gen_call_r_64(Bytes *s, Register r);

#define gen_little_endian_64(s, big_endian) gen_little_endian(s, big_endian, 4)

// ************************* 32-bits *************************
ELF_DEF void gen_add_32_r_imm_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_32_r_imm_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_32_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_32_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_32(Bytes *s, Register r);
ELF_DEF void gen_dec_32(Bytes *s, Register r);

ELF_DEF void gen_imul_32_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_32_long_form(Bytes *s, Register r, size_t mul);

ELF_DEF void gen_div_32(Bytes *s, Register r);

ELF_DEF void gen_and_32_r_imm_short_form(Bytes *s, Register r, char and);
ELF_DEF void gen_and_32_r_imm_long_form(Bytes *s, Register r, size_t and);

ELF_DEF void gen_or_32_r_imm_short_form(Bytes *s, Register r, char or);
ELF_DEF void gen_or_32_r_imm_long_form(Bytes *s, Register r, size_t or);

ELF_DEF void gen_not_32(Bytes *s, Register r);

ELF_DEF void gen_shr_32_r_1(Bytes *s, Register r);
ELF_DEF void gen_shr_32_r_imm(Bytes *s, Register r, char shr);
ELF_DEF void gen_shr_32_r_cl(Bytes *s, Register r);

ELF_DEF void gen_shl_32_r_1(Bytes *s, Register r);
ELF_DEF void gen_shl_32_r_imm(Bytes *s, Register r, char shl);
ELF_DEF void gen_shl_32_r_cl(Bytes *s, Register r);

ELF_DEF void gen_sar_32_r_1(Bytes *s, Register r);
ELF_DEF void gen_sar_32_r_imm(Bytes *s, Register r, char sar);
ELF_DEF void gen_sar_32_r_cl(Bytes *s, Register r);

ELF_DEF void gen_cmp_32_r_imm_short_form(Bytes *s, Register r, char cmp);
ELF_DEF void gen_cmp_32_r_imm_long_form(Bytes *s, Register r, size_t cmp);

ELF_DEF void gen_push_32(Bytes *s, Register r);
ELF_DEF void gen_pop_32(Bytes *s, Register r);

ELF_DEF void gen_jmp_r_32(Bytes *s, Register r);

ELF_DEF void gen_call_r_32(Bytes *s, Register r);

#define gen_little_endian_32(s, big_endian) gen_little_endian(s, big_endian, 4)

// ************************* 16-bits *************************
ELF_DEF void gen_add_16_r_imm_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_16_r_imm_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_16_r_imm_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_16_r_imm_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_16(Bytes *s, Register r);
ELF_DEF void gen_dec_16(Bytes *s, Register r);

ELF_DEF void gen_imul_16_r_imm_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_16_r_imm_long_form(Bytes *s, Register r, size_t mul);

ELF_DEF void gen_div_16(Bytes *s, Register r);

ELF_DEF void gen_and_16_r_imm_short_form(Bytes *s, Register r, char and);
ELF_DEF void gen_and_16_r_imm_long_form(Bytes *s, Register r, size_t and);

ELF_DEF void gen_or_16_r_imm_short_form(Bytes *s, Register r, char or);
ELF_DEF void gen_or_16_r_imm_long_form(Bytes *s, Register r, size_t or);

ELF_DEF void gen_not_16(Bytes *s, Register r);

ELF_DEF void gen_shr_16_r_1(Bytes *s, Register r);
ELF_DEF void gen_shr_16_r_imm(Bytes *s, Register r, char shr);
ELF_DEF void gen_shr_16_r_cl(Bytes *s, Register r);

ELF_DEF void gen_shl_16_r_1(Bytes *s, Register r);
ELF_DEF void gen_shl_16_r_imm(Bytes *s, Register r, char shl);
ELF_DEF void gen_shl_16_r_cl(Bytes *s, Register r);

ELF_DEF void gen_sar_16_r_1(Bytes *s, Register r);
ELF_DEF void gen_sar_16_r_imm(Bytes *s, Register r, char sar);
ELF_DEF void gen_sar_16_r_cl(Bytes *s, Register r);

ELF_DEF void gen_cmp_16_r_imm_short_form(Bytes *s, Register r, char cmp);
ELF_DEF void gen_cmp_16_r_imm_long_form(Bytes *s, Register r, size_t cmp);

ELF_DEF void gen_push_16(Bytes *s, Register r);
ELF_DEF void gen_pop_16(Bytes *s, Register r);

ELF_DEF void gen_jmp_r_16(Bytes *s, Register r);

ELF_DEF void gen_call_r_16(Bytes *s, Register r);

#define gen_little_endian_16(s, big_endian) gen_little_endian(s, big_endian, 2)

// ************************* 8-bits *************************
ELF_DEF void gen_add_r_imm_8(Bytes *s, Register r, char add);
ELF_DEF void gen_sub_r_imm_8(Bytes *s, Register r, char sub);

ELF_DEF void gen_inc_8(Bytes *s, Register r);
ELF_DEF void gen_dec_8(Bytes *s, Register r);

ELF_DEF void gen_div_8(Bytes *s, Register r);

ELF_DEF void gen_and_r_imm_8(Bytes *s, Register r, char and);

ELF_DEF void gen_or_r_imm_8(Bytes *s, Register r, char or);

ELF_DEF void gen_not_8(Bytes *s, Register r);

ELF_DEF void gen_shr_8_r_1(Bytes *s, Register r);
ELF_DEF void gen_shr_8_r_imm(Bytes *s, Register r, char shr);
ELF_DEF void gen_shr_8_r_cl(Bytes *s, Register r);

ELF_DEF void gen_shl_8_r_1(Bytes *s, Register r);
ELF_DEF void gen_shl_8_r_imm(Bytes *s, Register r, char shl);
ELF_DEF void gen_shl_8_r_cl(Bytes *s, Register r);

ELF_DEF void gen_sar_8_r_1(Bytes *s, Register r);
ELF_DEF void gen_sar_8_r_imm(Bytes *s, Register r, char sar);
ELF_DEF void gen_sar_8_r_cl(Bytes *s, Register r);

ELF_DEF void gen_cmp_r_imm_8(Bytes *s, Register r, char cmp);

ELF_DEF void gen_push_8(Bytes *s, Register r);
ELF_DEF void gen_pop_8(Bytes *s, Register r);

ELF_DEF void gen_jmp_r_8(Bytes *s, Register r);

ELF_DEF void gen_call_r_8(Bytes *s, Register r);

#define gen_little_endian_8(s, big_endian) gen_little_endian(s, big_endian, 1)

#endif // ELFGEN_H_

#ifdef ELFGEN_IMPLEMENTATION

// Largely copied from the nob_da_append_many macro in nob.h, mildly modified:
// 1. It is simplified.
// 2. It is implemented as a function, rather than a macro, since it sees no real use in this codebase, other than appending bytes.
// https://github.com/tsoding/nob.h/blob/main/nob.h
ELF_DEF void append_bytes(Bytes *s, const char *bytes, size_t len) {
  if (s->count + len > s->capacity) {
    if (s->capacity == 0) {
      s->capacity = DA_INIT_CAPACITY;
    }
    while (s->count + len > s->capacity) {
      s->capacity *= 2;
    }
    s->items = realloc(s->items, s->capacity);
  }
  memcpy(s->items + s->count, bytes, len);
  s->count += len;
}

ELF_DEF void gen_little_endian(Bytes *s, size_t big_endian, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = (big_endian >> (i * 8)) & 0xFF;
    da_append(s, c);
  }
}

// ************************* ret etc *************************
ELF_DEF void gen_ret(Bytes *s) {
  da_append(s, 0xc3);
}

ELF_DEF void gen_ret_imm(Bytes *s, size_t ret) {
  da_append(s, 0xc2);
  gen_little_endian(s, ret, 2);
}

// ************************* jmp etc *************************
ELF_DEF void gen_jmp_imm_short_form(Bytes *s, char jmp) {
  da_append(s, 0xeb);
  da_append(s, jmp - 1);
}

ELF_DEF void gen_jmp_imm_long_form(Bytes *s, size_t jmp) {
  da_append(s, 0xe9);
  gen_little_endian(s, jmp - 5, 4);
}

ELF_DEF void gen_je_imm_short_form(Bytes *s, char je) {
  da_append(s, 0x74);
  da_append(s, je - 2);
}

ELF_DEF void gen_je_imm_long_form(Bytes *s, size_t je) {
  append_byets(s, "\x0f\x84", 2);
  gen_little_endian(s, je - 6, 4);
}

ELF_DEF void gen_jne_imm_short_form(Bytes *s, char jne) {
  da_append(s, 0x75);
  da_append(s, jne - 2);
}

ELF_DEF void gen_jne_imm_long_form(Bytes *s, size_t jne) {
  append_bytes(s, "\x0f\x85", 2);
  gen_little_endian(s, jne - 6, 4);
}

ELF_DEF void gen_jg_imm_short_form(Bytes *s, char jg) {
  da_append(s, 0x7f);
  da_append(s, jg - 2);
}

ELF_DEF void gen_jg_imm_long_form(Bytes *s, size_t jg) {
  append_bytes(s, "\x0f\x8f", 2);
  gen_little_endian(s, jg - 6, 4);
}

ELF_DEF void gen_jge_imm_short_form(Bytes *s, char jge) {
  da_append(s, 0x7d);
  da_append(s, jge - 2);
}

ELF_DEF void gen_jge_imm_long_form(Bytes *s, size_t jge) {
  append_bytes(s, "\x0f\x8d", 2);
  gen_little_endian(s, jge - 6, 4);
}

ELF_DEF void gen_jl_imm_short_form(Bytes *s, char jl) {
  da_append(s, 0x7c);
  da_append(s, jl - 2);
}

ELF_DEF void gen_jl_imm_long_form(Bytes *s, size_t jl) {
  append_bytes(s, "\x0f\x8c", 2);
  gen_little_endian(s, jl - 6, 4);
}

ELF_DEF void gen_jle_imm_short_form(Bytes *s, char jle) {
  da_append(s, 0x7e);
  da_append(s, jle - 2);
  
}

ELF_DEF void gen_jle_imm_long_form(Bytes *s, size_t jle) {
  append_bytes(s, "\x0f\x8e", 2);
  gen_little_endian(s, jle - 6, 4);
  
}

ELF_DEF void gen_call_imm_short_form(Bytes *s, char call) {
  // Apparently doesn/t exist?
}

ELF_DEF void gen_call_imm_long_form(Bytes *s, size_t call) {
  da_append(s, 0xe8);
  gen_little_endian(s, call - 5, 4);
  
}

ELF_DEF void gen_push_imm_short_form(Bytes *s, char push) {
  da_append(s, 0x6a);
  da_append(s, push);
}

ELF_DEF void gen_push_imm_long_form(Bytes *s, size_t push) {
  da_append(s, 0x68);
  gen_little_endian(s, push, 4);
}

// ************************* 64-bits *************************
ELF_DEF void gen_add_64_r_imm_short_form(Bytes *s, Register r, char add) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x83\xc0", 3); break;
  case RBX: append_bytes(s, "\x48\x83\xc3", 3); break;
  case RCX: append_bytes(s, "\x48\x83\xc1", 3); break;
  case RDX: append_bytes(s, "\x48\x83\xc2", 3); break;
  case RSI: append_bytes(s, "\x48\x83\xc6", 3); break;
  case RDI: append_bytes(s, "\x48\x83\xc7", 3); break;
  case RBP: append_bytes(s, "\x48\x83\xc5", 3); break;
  case RSP: append_bytes(s, "\x48\x83\xc4", 3); break;
  case R8:  append_bytes(s, "\x49\x83\xc0", 3); break;
  case R9:  append_bytes(s, "\x49\x83\xc1", 3); break;
  case R10: append_bytes(s, "\x49\x83\xc2", 3); break;
  case R11: append_bytes(s, "\x49\x83\xc3", 3); break;
  case R12: append_bytes(s, "\x49\x83\xc4", 3); break;
  case R13: append_bytes(s, "\x49\x83\xc5", 3); break;
  case R14: append_bytes(s, "\x49\x83\xc6", 3); break;
  case R15: append_bytes(s, "\x49\x83\xc7", 3); break;
  }

  da_append(s, add);
}

ELF_DEF void gen_add_64_r_imm_long_form(Bytes *s, Register r, size_t add) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x05",     2); break;
  case RBX: append_bytes(s, "\x48\x81\xc3", 3); break;
  case RCX: append_bytes(s, "\x48\x81\xc1", 3); break;
  case RDX: append_bytes(s, "\x48\x81\xc2", 3); break;
  case RSI: append_bytes(s, "\x48\x81\xc6", 3); break;
  case RDI: append_bytes(s, "\x48\x81\xc7", 3); break;
  case RBP: append_bytes(s, "\x48\x81\xc5", 3); break;
  case RSP: append_bytes(s, "\x48\x81\xc4", 3); break;
  case R8:  append_bytes(s, "\x49\x81\xc0", 3); break;
  case R9:  append_bytes(s, "\x49\x81\xc1", 3); break;
  case R10: append_bytes(s, "\x49\x81\xc2", 3); break;
  case R11: append_bytes(s, "\x49\x81\xc3", 3); break;
  case R12: append_bytes(s, "\x49\x81\xc4", 3); break;
  case R13: append_bytes(s, "\x49\x81\xc5", 3); break;
  case R14: append_bytes(s, "\x49\x81\xc6", 3); break;
  case R15: append_bytes(s, "\x49\x81\xc7", 3); break;
  }

  gen_little_endian(s, add, 4);
}

ELF_DEF void gen_sub_64_r_imm_short_form(Bytes *s, Register r, char sub) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x83\xe8", 3); break;
  case RBX: append_bytes(s, "\x48\x83\xeb", 3); break;
  case RCX: append_bytes(s, "\x48\x83\xe9", 3); break;
  case RDX: append_bytes(s, "\x48\x83\xea", 3); break;
  case RSI: append_bytes(s, "\x48\x83\xee", 3); break;
  case RDI: append_bytes(s, "\x48\x83\xef", 3); break;
  case RBP: append_bytes(s, "\x48\x83\xed", 3); break;
  case RSP: append_bytes(s, "\x48\x83\xec", 3); break;
  case R8:  append_bytes(s, "\x49\x83\xe8", 3); break;
  case R9:  append_bytes(s, "\x49\x83\xe9", 3); break;
  case R10: append_bytes(s, "\x49\x83\xea", 3); break;
  case R11: append_bytes(s, "\x49\x83\xeb", 3); break;
  case R12: append_bytes(s, "\x49\x83\xec", 3); break;
  case R13: append_bytes(s, "\x49\x83\xed", 3); break;
  case R14: append_bytes(s, "\x49\x83\xee", 3); break;
  case R15: append_bytes(s, "\x49\x83\xef", 3); break;
  }

  da_append(s, sub);
}

ELF_DEF void gen_sub_64_r_imm_long_form(Bytes *s, Register r, size_t sub) {
  switch (r) {
  case RAX: append_bytes(s,  "\x48\x2d",     2); break;
  case RBX: append_bytes(s,  "\x48\x81\xeb", 3); break;
  case RCX: append_bytes(s,  "\x48\x81\xe9", 3); break;
  case RDX: append_bytes(s,  "\x48\x81\xea", 3); break;
  case RSI: append_bytes(s,  "\x48\x81\xee", 3); break;
  case RDI: append_bytes(s,  "\x48\x81\xef", 3); break;
  case RBP: append_bytes(s,  "\x48\x81\xed", 3); break;
  case RSP: append_bytes(s,  "\x48\x81\xec", 3); break;
  case R8:  append_bytes(s,  "\x49\x81\xe8", 3); break;
  case R9:  append_bytes(s,  "\x49\x81\xe9", 3); break;
  case R10: append_bytes(s,  "\x49\x81\xea", 3); break;
  case R11: append_bytes(s,  "\x49\x81\xeb", 3); break;
  case R12: append_bytes(s,  "\x49\x81\xec", 3); break;
  case R13: append_bytes(s,  "\x49\x81\xed", 3); break;
  case R14: append_bytes(s,  "\x49\x81\xee", 3); break;
  case R15: append_bytes(s,  "\x49\x81\xef", 3); break;
  }

  gen_little_endian(s, sub, 4);
}

ELF_DEF void gen_inc_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "48\xff\xc0", 3); break;
  case RBX: append_bytes(s, "48\xff\xc3", 3); break;
  case RCX: append_bytes(s, "48\xff\xc1", 3); break;
  case RDX: append_bytes(s, "48\xff\xc2", 3); break;
  case RSI: append_bytes(s, "48\xff\xc6", 3); break;
  case RDI: append_bytes(s, "48\xff\xc7", 3); break;
  case RBP: append_bytes(s, "48\xff\xc5", 3); break;
  case RSP: append_bytes(s, "48\xff\xc4", 3); break;
  case R8:  append_bytes(s, "49\xff\xc0", 3); break;
  case R9:  append_bytes(s, "49\xff\xc1", 3); break;
  case R10: append_bytes(s, "49\xff\xc2", 3); break;
  case R11: append_bytes(s, "49\xff\xc3", 3); break;
  case R12: append_bytes(s, "49\xff\xc4", 3); break;
  case R13: append_bytes(s, "49\xff\xc5", 3); break;
  case R14: append_bytes(s, "49\xff\xc6", 3); break;
  case R15: append_bytes(s, "49\xff\xc7", 3); break;
  }
}

ELF_DEF void gen_dec_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xff\xc8", 3); break;
  case RBX: append_bytes(s, "\x48\xff\xcb", 3); break;
  case RCX: append_bytes(s, "\x48\xff\xc9", 3); break;
  case RDX: append_bytes(s, "\x48\xff\xca", 3); break;
  case RSI: append_bytes(s, "\x48\xff\xce", 3); break;
  case RDI: append_bytes(s, "\x48\xff\xcf", 3); break;
  case RBP: append_bytes(s, "\x48\xff\xcd", 3); break;
  case RSP: append_bytes(s, "\x48\xff\xcc", 3); break;
  case R8:  append_bytes(s, "\x49\xff\xc8", 3); break;
  case R9:  append_bytes(s, "\x49\xff\xc9", 3); break;
  case R10: append_bytes(s, "\x49\xff\xca", 3); break;
  case R11: append_bytes(s, "\x49\xff\xcb", 3); break;
  case R12: append_bytes(s, "\x49\xff\xcc", 3); break;
  case R13: append_bytes(s, "\x49\xff\xcd", 3); break;
  case R14: append_bytes(s, "\x49\xff\xce", 3); break;
  case R15: append_bytes(s, "\x49\xff\xcf", 3); break;
  }
}

ELF_DEF void gen_imul_64_r_imm_short_form(Bytes *s, Register r, char mul) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x6b\xc0", 3); break;
  case RBX: append_bytes(s, "\x48\x6b\xdb", 3); break;
  case RCX: append_bytes(s, "\x48\x6b\xc9", 3); break;
  case RDX: append_bytes(s, "\x48\x6b\xd2", 3); break;
  case RSI: append_bytes(s, "\x48\x6b\xf6", 3); break;
  case RDI: append_bytes(s, "\x48\x6b\xff", 3); break;
  case RBP: append_bytes(s, "\x48\x6b\xed", 3); break;
  case RSP: append_bytes(s, "\x48\x6b\xe4", 3); break;
  case R8:  append_bytes(s, "\x4d\x6b\xc0", 3); break;
  case R9:  append_bytes(s, "\x4d\x6b\xc9", 3); break;
  case R10: append_bytes(s, "\x4d\x6b\xd2", 3); break;
  case R11: append_bytes(s, "\x4d\x6b\xdb", 3); break;
  case R12: append_bytes(s, "\x4d\x6b\xe4", 3); break;
  case R13: append_bytes(s, "\x4d\x6b\xed", 3); break;
  case R14: append_bytes(s, "\x4d\x6b\xf6", 3); break;
  case R15: append_bytes(s, "\x4d\x6b\xff", 3); break;
  }

  da_append(s, mul);
}

ELF_DEF void gen_imul_64_r_imm_long_form(Bytes *s, Register r, size_t mul) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x69\xc0", 3); break;
  case RBX: append_bytes(s, "\x48\x69\xdb", 3); break;
  case RCX: append_bytes(s, "\x48\x69\xc9", 3); break;
  case RDX: append_bytes(s, "\x48\x69\xd2", 3); break;
  case RSI: append_bytes(s, "\x48\x69\xf6", 3); break;
  case RDI: append_bytes(s, "\x48\x69\xff", 3); break;
  case RBP: append_bytes(s, "\x48\x69\xed", 3); break;
  case RSP: append_bytes(s, "\x48\x69\xe4", 3); break;
  case R8:  append_bytes(s, "\x4d\x69\xc0", 3); break;
  case R9:  append_bytes(s, "\x4d\x69\xc9", 3); break;
  case R10: append_bytes(s, "\x4d\x69\xd2", 3); break;
  case R11: append_bytes(s, "\x4d\x69\xdb", 3); break;
  case R12: append_bytes(s, "\x4d\x69\xe4", 3); break;
  case R13: append_bytes(s, "\x4d\x69\xed", 3); break;
  case R14: append_bytes(s, "\x4d\x69\xf6", 3); break;
  case R15: append_bytes(s, "\x4d\x69\xff", 3); break;
  }

  gen_little_endian(s, mul, 4);
}

ELF_DEF void gen_div_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xf7\xf0", 3); break;
  case RBX: append_bytes(s, "\x48\xf7\xf3", 3); break;
  case RCX: append_bytes(s, "\x48\xf7\xf1", 3); break;
  case RDX: append_bytes(s, "\x48\xf7\xf2", 3); break;
  case RSI: append_bytes(s, "\x48\xf7\xf6", 3); break;
  case RDI: append_bytes(s, "\x48\xf7\xf7", 3); break;
  case RBP: append_bytes(s, "\x48\xf7\xf5", 3); break;
  case RSP: append_bytes(s, "\x48\xf7\xf4", 3); break;
  case R8:  append_bytes(s, "\x49\xf7\xf0", 3); break;
  case R9:  append_bytes(s, "\x49\xf7\xf1", 3); break;
  case R10: append_bytes(s, "\x49\xf7\xf2", 3); break;
  case R11: append_bytes(s, "\x49\xf7\xf3", 3); break;
  case R12: append_bytes(s, "\x49\xf7\xf4", 3); break;
  case R13: append_bytes(s, "\x49\xf7\xf5", 3); break;
  case R14: append_bytes(s, "\x49\xf7\xf6", 3); break;
  case R15: append_bytes(s, "\x49\xf7\xf7", 3); break;
  }
}

ELF_DEF void gen_and_64_r_imm_short_form(Bytes *s, Register r, char and) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x83\xe0", 3); break;
  case RBX: append_bytes(s, "\x48\x83\xe3", 3); break;
  case RCX: append_bytes(s, "\x48\x83\xe1", 3); break;
  case RDX: append_bytes(s, "\x48\x83\xe2", 3); break;
  case RSI: append_bytes(s, "\x48\x83\xe6", 3); break;
  case RDI: append_bytes(s, "\x48\x83\xe7", 3); break;
  case RBP: append_bytes(s, "\x48\x83\xe5", 3); break;
  case RSP: append_bytes(s, "\x48\x83\xe4", 3); break;
  case R8:  append_bytes(s, "\x49\x83\xe0", 3); break;
  case R9:  append_bytes(s, "\x49\x83\xe1", 3); break;
  case R10: append_bytes(s, "\x49\x83\xe2", 3); break;
  case R11: append_bytes(s, "\x49\x83\xe3", 3); break;
  case R12: append_bytes(s, "\x49\x83\xe4", 3); break;
  case R13: append_bytes(s, "\x49\x83\xe5", 3); break;
  case R14: append_bytes(s, "\x49\x83\xe6", 3); break;
  case R15: append_bytes(s, "\x49\x83\xe7", 3); break;
  }

  da_append(s, and);
}

ELF_DEF void gen_and_64_r_imm_long_form(Bytes *s, Register r, size_t and) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x25",     2); break;
  case RBX: append_bytes(s, "\x48\x81\xe3", 3); break;
  case RCX: append_bytes(s, "\x48\x81\xe1", 3); break;
  case RDX: append_bytes(s, "\x48\x81\xe2", 3); break;
  case RSI: append_bytes(s, "\x48\x81\xe6", 3); break;
  case RDI: append_bytes(s, "\x48\x81\xe7", 3); break;
  case RBP: append_bytes(s, "\x48\x81\xe5", 3); break;
  case RSP: append_bytes(s, "\x48\x81\xe4", 3); break;
  case R8:  append_bytes(s, "\x49\x81\xe0", 3); break;
  case R9:  append_bytes(s, "\x49\x81\xe1", 3); break;
  case R10: append_bytes(s, "\x49\x81\xe2", 3); break;
  case R11: append_bytes(s, "\x49\x81\xe3", 3); break;
  case R12: append_bytes(s, "\x49\x81\xe4", 3); break;
  case R13: append_bytes(s, "\x49\x81\xe5", 3); break;
  case R14: append_bytes(s, "\x49\x81\xe6", 3); break;
  case R15: append_bytes(s, "\x49\x81\xe7", 3); break;
  }

  gen_little_endian(s, and, 4);
}

ELF_DEF void gen_or_64_r_imm_short_form(Bytes *s, Register r, char or) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x83\xc8", 3); break;
  case RBX: append_bytes(s, "\x48\x83\xcb", 3); break;
  case RCX: append_bytes(s, "\x48\x83\xc9", 3); break;
  case RDX: append_bytes(s, "\x48\x83\xca", 3); break;
  case RSI: append_bytes(s, "\x48\x83\xce", 3); break;
  case RDI: append_bytes(s, "\x48\x83\xcf", 3); break;
  case RBP: append_bytes(s, "\x48\x83\xcd", 3); break;
  case RSP: append_bytes(s, "\x48\x83\xcc", 3); break;
  case R8:  append_bytes(s, "\x49\x83\xc8", 3); break;
  case R9:  append_bytes(s, "\x49\x83\xc9", 3); break;
  case R10: append_bytes(s, "\x49\x83\xca", 3); break;
  case R11: append_bytes(s, "\x49\x83\xcb", 3); break;
  case R12: append_bytes(s, "\x49\x83\xcc", 3); break;
  case R13: append_bytes(s, "\x49\x83\xcd", 3); break;
  case R14: append_bytes(s, "\x49\x83\xce", 3); break;
  case R15: append_bytes(s, "\x49\x83\xcf", 3); break;
  }

  da_append(s, or);
}

ELF_DEF void gen_or_64_r_imm_long_form(Bytes *s, Register r, size_t or) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x0d",     2); break;
  case RBX: append_bytes(s, "\x48\x81\xcb", 3); break;
  case RCX: append_bytes(s, "\x48\x81\xc9", 3); break;
  case RDX: append_bytes(s, "\x48\x81\xca", 3); break;
  case RSI: append_bytes(s, "\x48\x81\xce", 3); break;
  case RDI: append_bytes(s, "\x48\x81\xcf", 3); break;
  case RBP: append_bytes(s, "\x48\x81\xcd", 3); break;
  case RSP: append_bytes(s, "\x48\x81\xcc", 3); break;
  case R8:  append_bytes(s, "\x49\x81\xc8", 3); break;
  case R9:  append_bytes(s, "\x49\x81\xc9", 3); break;
  case R10: append_bytes(s, "\x49\x81\xca", 3); break;
  case R11: append_bytes(s, "\x49\x81\xcb", 3); break;
  case R12: append_bytes(s, "\x49\x81\xcc", 3); break;
  case R13: append_bytes(s, "\x49\x81\xcd", 3); break;
  case R14: append_bytes(s, "\x49\x81\xce", 3); break;
  case R15: append_bytes(s, "\x49\x81\xcf", 3); break;
  }

  gen_little_endian(s, or, 4);
}

ELF_DEF void gen_not_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xf7\xd0", 3); break;
  case RBX: append_bytes(s, "\x48\xf7\xd3", 3); break;
  case RCX: append_bytes(s, "\x48\xf7\xd1", 3); break;
  case RDX: append_bytes(s, "\x48\xf7\xd2", 3); break;
  case RSI: append_bytes(s, "\x48\xf7\xd6", 3); break;
  case RDI: append_bytes(s, "\x48\xf7\xd7", 3); break;
  case RBP: append_bytes(s, "\x48\xf7\xd5", 3); break;
  case RSP: append_bytes(s, "\x48\xf7\xd4", 3); break;
  case R8:  append_bytes(s, "\x49\xf7\xd0", 3); break;
  case R9:  append_bytes(s, "\x49\xf7\xd1", 3); break;
  case R10: append_bytes(s, "\x49\xf7\xd2", 3); break;
  case R11: append_bytes(s, "\x49\xf7\xd3", 3); break;
  case R12: append_bytes(s, "\x49\xf7\xd4", 3); break;
  case R13: append_bytes(s, "\x49\xf7\xd5", 3); break;
  case R14: append_bytes(s, "\x49\xf7\xd6", 3); break;
  case R15: append_bytes(s, "\x49\xf7\xd7", 3); break;
  }
}

ELF_DEF void gen_shr_64_r_1(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd1\xe8", 3); break;
  case RBX: append_bytes(s, "\x48\xd1\xeb", 3); break;
  case RCX: append_bytes(s, "\x48\xd1\xe9", 3); break;
  case RDX: append_bytes(s, "\x48\xd1\xea", 3); break;
  case RSI: append_bytes(s, "\x48\xd1\xee", 3); break;
  case RDI: append_bytes(s, "\x48\xd1\xef", 3); break;
  case RBP: append_bytes(s, "\x48\xd1\xed", 3); break;
  case RSP: append_bytes(s, "\x48\xd1\xec", 3); break;
  case R8:  append_bytes(s, "\x49\xd1\xe8", 3); break;
  case R9:  append_bytes(s, "\x49\xd1\xe9", 3); break;
  case R10: append_bytes(s, "\x49\xd1\xea", 3); break;
  case R11: append_bytes(s, "\x49\xd1\xeb", 3); break;
  case R12: append_bytes(s, "\x49\xd1\xec", 3); break;
  case R13: append_bytes(s, "\x49\xd1\xed", 3); break;
  case R14: append_bytes(s, "\x49\xd1\xee", 3); break;
  case R15: append_bytes(s, "\x49\xd1\xef", 3); break;
  }
}

ELF_DEF void gen_shr_64_r_imm(Bytes *s, Register r, char shr) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xc1\xe8", 3); break;
  case RBX: append_bytes(s, "\x48\xc1\xeb", 3); break;
  case RCX: append_bytes(s, "\x48\xc1\xe9", 3); break;
  case RDX: append_bytes(s, "\x48\xc1\xea", 3); break;
  case RSI: append_bytes(s, "\x48\xc1\xee", 3); break;
  case RDI: append_bytes(s, "\x48\xc1\xef", 3); break;
  case RBP: append_bytes(s, "\x48\xc1\xed", 3); break;
  case RSP: append_bytes(s, "\x48\xc1\xec", 3); break;
  case R8:  append_bytes(s, "\x49\xc1\xe8", 3); break;
  case R9:  append_bytes(s, "\x49\xc1\xe9", 3); break;
  case R10: append_bytes(s, "\x49\xc1\xea", 3); break;
  case R11: append_bytes(s, "\x49\xc1\xeb", 3); break;
  case R12: append_bytes(s, "\x49\xc1\xec", 3); break;
  case R13: append_bytes(s, "\x49\xc1\xed", 3); break;
  case R14: append_bytes(s, "\x49\xc1\xee", 3); break;
  case R15: append_bytes(s, "\x49\xc1\xef", 3); break;
  }

  da_append(s, shr);
}

ELF_DEF void gen_shr_64_r_cl(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd3\xe8", 3); break;
  case RBX: append_bytes(s, "\x48\xd3\xeb", 3); break;
  case RCX: append_bytes(s, "\x48\xd3\xe9", 3); break;
  case RDX: append_bytes(s, "\x48\xd3\xea", 3); break;
  case RSI: append_bytes(s, "\x48\xd3\xee", 3); break;
  case RDI: append_bytes(s, "\x48\xd3\xef", 3); break;
  case RBP: append_bytes(s, "\x48\xd3\xed", 3); break;
  case RSP: append_bytes(s, "\x48\xd3\xec", 3); break;
  case R8:  append_bytes(s, "\x49\xd3\xe8", 3); break;
  case R9:  append_bytes(s, "\x49\xd3\xe9", 3); break;
  case R10: append_bytes(s, "\x49\xd3\xea", 3); break;
  case R11: append_bytes(s, "\x49\xd3\xeb", 3); break;
  case R12: append_bytes(s, "\x49\xd3\xec", 3); break;
  case R13: append_bytes(s, "\x49\xd3\xed", 3); break;
  case R14: append_bytes(s, "\x49\xd3\xee", 3); break;
  case R15: append_bytes(s, "\x49\xd3\xef", 3); break;
  }
}

ELF_DEF void gen_shl_64_r_1(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd1\xe0", 3); break;
  case RBX: append_bytes(s, "\x48\xd1\xe3", 3); break;
  case RCX: append_bytes(s, "\x48\xd1\xe1", 3); break;
  case RDX: append_bytes(s, "\x48\xd1\xe2", 3); break;
  case RSI: append_bytes(s, "\x48\xd1\xe6", 3); break;
  case RDI: append_bytes(s, "\x48\xd1\xe7", 3); break;
  case RBP: append_bytes(s, "\x48\xd1\xe5", 3); break;
  case RSP: append_bytes(s, "\x48\xd1\xe4", 3); break;
  case R8:  append_bytes(s, "\x49\xd1\xe0", 3); break;
  case R9:  append_bytes(s, "\x49\xd1\xe1", 3); break;
  case R10: append_bytes(s, "\x49\xd1\xe2", 3); break;
  case R11: append_bytes(s, "\x49\xd1\xe3", 3); break;
  case R12: append_bytes(s, "\x49\xd1\xe4", 3); break;
  case R13: append_bytes(s, "\x49\xd1\xe5", 3); break;
  case R14: append_bytes(s, "\x49\xd1\xe6", 3); break;
  case R15: append_bytes(s, "\x49\xd1\xe7", 3); break;
  }
}

ELF_DEF void gen_shl_64_r_imm(Bytes *s, Register r, char shl) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xc1\xe0", 3); break;
  case RBX: append_bytes(s, "\x48\xc1\xe3", 3); break;
  case RCX: append_bytes(s, "\x48\xc1\xe1", 3); break;
  case RDX: append_bytes(s, "\x48\xc1\xe2", 3); break;
  case RSI: append_bytes(s, "\x48\xc1\xe6", 3); break;
  case RDI: append_bytes(s, "\x48\xc1\xe7", 3); break;
  case RBP: append_bytes(s, "\x48\xc1\xe5", 3); break;
  case RSP: append_bytes(s, "\x48\xc1\xe4", 3); break;
  case R8:  append_bytes(s, "\x49\xc1\xe0", 3); break;
  case R9:  append_bytes(s, "\x49\xc1\xe1", 3); break;
  case R10: append_bytes(s, "\x49\xc1\xe2", 3); break;
  case R11: append_bytes(s, "\x49\xc1\xe3", 3); break;
  case R12: append_bytes(s, "\x49\xc1\xe4", 3); break;
  case R13: append_bytes(s, "\x49\xc1\xe5", 3); break;
  case R14: append_bytes(s, "\x49\xc1\xe6", 3); break;
  case R15: append_bytes(s, "\x49\xc1\xe7", 3); break;
  }

  da_append(s, shl);
}

ELF_DEF void gen_shl_64_r_cl(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd3\xe0", 3); break;
  case RBX: append_bytes(s, "\x48\xd3\xe3", 3); break;
  case RCX: append_bytes(s, "\x48\xd3\xe1", 3); break;
  case RDX: append_bytes(s, "\x48\xd3\xe2", 3); break;
  case RSI: append_bytes(s, "\x48\xd3\xe6", 3); break;
  case RDI: append_bytes(s, "\x48\xd3\xe7", 3); break;
  case RBP: append_bytes(s, "\x48\xd3\xe5", 3); break;
  case RSP: append_bytes(s, "\x48\xd3\xe4", 3); break;
  case R8:  append_bytes(s, "\x49\xd3\xe0", 3); break;
  case R9:  append_bytes(s, "\x49\xd3\xe1", 3); break;
  case R10: append_bytes(s, "\x49\xd3\xe2", 3); break;
  case R11: append_bytes(s, "\x49\xd3\xe3", 3); break;
  case R12: append_bytes(s, "\x49\xd3\xe4", 3); break;
  case R13: append_bytes(s, "\x49\xd3\xe5", 3); break;
  case R14: append_bytes(s, "\x49\xd3\xe6", 3); break;
  case R15: append_bytes(s, "\x49\xd3\xe7", 3); break;
  }
}

ELF_DEF void gen_sar_64_r_1(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd1\xf8", 3); break;
  case RBX: append_bytes(s, "\x48\xd1\xfb", 3); break;
  case RCX: append_bytes(s, "\x48\xd1\xf9", 3); break;
  case RDX: append_bytes(s, "\x48\xd1\xfa", 3); break;
  case RSI: append_bytes(s, "\x48\xd1\xfe", 3); break;
  case RDI: append_bytes(s, "\x48\xd1\xff", 3); break;
  case RBP: append_bytes(s, "\x48\xd1\xfd", 3); break;
  case RSP: append_bytes(s, "\x48\xd1\xfc", 3); break;
  case R8:  append_bytes(s, "\x49\xd1\xf8", 3); break;
  case R9:  append_bytes(s, "\x49\xd1\xf9", 3); break;
  case R10: append_bytes(s, "\x49\xd1\xfa", 3); break;
  case R11: append_bytes(s, "\x49\xd1\xfb", 3); break;
  case R12: append_bytes(s, "\x49\xd1\xfc", 3); break;
  case R13: append_bytes(s, "\x49\xd1\xfd", 3); break;
  case R14: append_bytes(s, "\x49\xd1\xfe", 3); break;
  case R15: append_bytes(s, "\x49\xd1\xff", 3); break;
  }
}

ELF_DEF void gen_sar_64_r_imm(Bytes *s, Register r, char sar) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xc1\xf8\x0a", 4); break;
  case RBX: append_bytes(s, "\x48\xc1\xfb\x0a", 4); break;
  case RCX: append_bytes(s, "\x48\xc1\xf9\x0a", 4); break;
  case RDX: append_bytes(s, "\x48\xc1\xfa\x0a", 4); break;
  case RSI: append_bytes(s, "\x48\xc1\xfe\x0a", 4); break;
  case RDI: append_bytes(s, "\x48\xc1\xff\x0a", 4); break;
  case RBP: append_bytes(s, "\x48\xc1\xfd\x0a", 4); break;
  case RSP: append_bytes(s, "\x48\xc1\xfc\x0a", 4); break;
  case R8:  append_bytes(s, "\x49\xc1\xf8\x0a", 4); break;
  case R9:  append_bytes(s, "\x49\xc1\xf9\x0a", 4); break;
  case R10: append_bytes(s, "\x49\xc1\xfa\x0a", 4); break;
  case R11: append_bytes(s, "\x49\xc1\xfb\x0a", 4); break;
  case R12: append_bytes(s, "\x49\xc1\xfc\x0a", 4); break;
  case R13: append_bytes(s, "\x49\xc1\xfd\x0a", 4); break;
  case R14: append_bytes(s, "\x49\xc1\xfe\x0a", 4); break;
  case R15: append_bytes(s, "\x49\xc1\xff\x0a", 4); break;
  }

  da_append(s, sar);
}

ELF_DEF void gen_sar_64_r_cl(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\xd3\xf8", 3); break;
  case RBX: append_bytes(s, "\x48\xd3\xfb", 3); break;
  case RCX: append_bytes(s, "\x48\xd3\xf9", 3); break;
  case RDX: append_bytes(s, "\x48\xd3\xfa", 3); break;
  case RSI: append_bytes(s, "\x48\xd3\xfe", 3); break;
  case RDI: append_bytes(s, "\x48\xd3\xff", 3); break;
  case RBP: append_bytes(s, "\x48\xd3\xfd", 3); break;
  case RSP: append_bytes(s, "\x48\xd3\xfc", 3); break;
  case R8:  append_bytes(s, "\x49\xd3\xf8", 3); break;
  case R9:  append_bytes(s, "\x49\xd3\xf9", 3); break;
  case R10: append_bytes(s, "\x49\xd3\xfa", 3); break;
  case R11: append_bytes(s, "\x49\xd3\xfb", 3); break;
  case R12: append_bytes(s, "\x49\xd3\xfc", 3); break;
  case R13: append_bytes(s, "\x49\xd3\xfd", 3); break;
  case R14: append_bytes(s, "\x49\xd3\xfe", 3); break;
  case R15: append_bytes(s, "\x49\xd3\xff", 3); break;
  }
}

ELF_DEF void gen_cmp_64_r_imm_short_form(Bytes *s, Register r, char cmp) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x83\xf8", 3); break;
  case RBX: append_bytes(s, "\x48\x83\xfb", 3); break;
  case RCX: append_bytes(s, "\x48\x83\xf9", 3); break;
  case RDX: append_bytes(s, "\x48\x83\xfa", 3); break;
  case RSI: append_bytes(s, "\x48\x83\xfe", 3); break;
  case RDI: append_bytes(s, "\x48\x83\xff", 3); break;
  case RBP: append_bytes(s, "\x48\x83\xfd", 3); break;
  case RSP: append_bytes(s, "\x48\x83\xfc", 3); break;
  case R8:  append_bytes(s, "\x49\x83\xf8", 3); break;
  case R9:  append_bytes(s, "\x49\x83\xf9", 3); break;
  case R10: append_bytes(s, "\x49\x83\xfa", 3); break;
  case R11: append_bytes(s, "\x49\x83\xfb", 3); break;
  case R12: append_bytes(s, "\x49\x83\xfc", 3); break;
  case R13: append_bytes(s, "\x49\x83\xfd", 3); break;
  case R14: append_bytes(s, "\x49\x83\xfe", 3); break;
  case R15: append_bytes(s, "\x49\x83\xff", 3); break;
  }

  da_append(s, cmp);
}

ELF_DEF void gen_cmp_64_r_imm_long_form(Bytes *s, Register r, size_t cmp) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x3d",     2); break;
  case RBX: append_bytes(s, "\x48\x81\xfb", 3); break;
  case RCX: append_bytes(s, "\x48\x81\xf9", 3); break;
  case RDX: append_bytes(s, "\x48\x81\xfa", 3); break;
  case RSI: append_bytes(s, "\x48\x81\xfe", 3); break;
  case RDI: append_bytes(s, "\x48\x81\xff", 3); break;
  case RBP: append_bytes(s, "\x48\x81\xfd", 3); break;
  case RSP: append_bytes(s, "\x48\x81\xfc", 3); break;
  case R8:  append_bytes(s, "\x49\x81\xf8", 3); break;
  case R9:  append_bytes(s, "\x49\x81\xf9", 3); break;
  case R10: append_bytes(s, "\x49\x81\xfa", 3); break;
  case R11: append_bytes(s, "\x49\x81\xfb", 3); break;
  case R12: append_bytes(s, "\x49\x81\xfc", 3); break;
  case R13: append_bytes(s, "\x49\x81\xfd", 3); break;
  case R14: append_bytes(s, "\x49\x81\xfe", 3); break;
  case R15: append_bytes(s, "\x49\x81\xff", 3); break;
  }

  gen_little_endian(s, cmp, 4);
}

ELF_DEF void gen_push_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: da_append(s,    0x50);          break;
  case RBX: da_append(s,    0x53);          break;
  case RCX: da_append(s,    0x51);          break;
  case RDX: da_append(s,    0x52);          break;
  case RSI: da_append(s,    0x56);          break;
  case RDI: da_append(s,    0x57);          break;
  case RBP: da_append(s,    0x55);          break;
  case RSP: da_append(s,    0x54);          break;
  case R8:  append_bytes(s, "\x41\x50", 2); break;
  case R9:  append_bytes(s, "\x41\x51", 2); break;
  case R10: append_bytes(s, "\x41\x52", 2); break;
  case R11: append_bytes(s, "\x41\x53", 2); break;
  case R12: append_bytes(s, "\x41\x54", 2); break;
  case R13: append_bytes(s, "\x41\x55", 2); break;
  case R14: append_bytes(s, "\x41\x56", 2); break;
  case R15: append_bytes(s, "\x41\x57", 2); break;
  }
}

ELF_DEF void gen_pop_64(Bytes *s, Register r) {
  switch (r) {
  case rax: da_append(s, 0x58); break;
  case rbx: da_append(s, 0x5b); break;
  case rcx: da_append(s, 0x59); break;
  case rdx: da_append(s, 0x5a); break;
  case rsi: da_append(s, 0x5e); break;
  case rdi: da_append(s, 0x5f); break;
  case rbp: da_append(s, 0x5d); break;
  case rsp: da_append(s, 0x5c); break;
  case r8: append_bytes(s, "\x41\x58", 2); break;
  case r9: append_bytes(s, "\x41\x59", 2); break;
  case r10: append_bytes(s, "\x41\x5a", 2); break;
  case r11: append_bytes(s, "\x41\x5b", 2); break;
  case r12: append_bytes(s, "\x41\x5c", 2); break;
  case r13: append_bytes(s, "\x41\x5d", 2); break;
  case r14: append_bytes(s, "\x41\x5e", 2); break;
  case r15: append_bytes(s, "\x41\x5f", 2); break;
  }
}

ELF_DEF void gen_jmp_r_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\xff\xe0", 2); break;
  case RBX: append_bytes(s, "\xff\xe3", 2); break;
  case RCX: append_bytes(s, "\xff\xe1", 2); break;
  case RDX: append_bytes(s, "\xff\xe2", 2); break;
  case RSI: append_bytes(s, "\xff\xe6", 2); break;
  case RDI: append_bytes(s, "\xff\xe7", 2); break;
  case RBP: append_bytes(s, "\xff\xe5", 2); break;
  case RSP: append_bytes(s, "\xff\xe4", 2); break;
  case R8: append_bytes(s, "\x41\xff\xe0", 3); break;
  case R9: append_bytes(s, "\x41\xff\xe1", 3); break;
  case R10: append_bytes(s, "\x41\xff\xe2", 3); break;
  case R11: append_bytes(s, "\x41\xff\xe3", 3); break;
  case R12: append_bytes(s, "\x41\xff\xe4", 3); break;
  case R13: append_bytes(s, "\x41\xff\xe5", 3); break;
  case R14: append_bytes(s, "\x41\xff\xe6", 3); break;
  case R15: append_bytes(s, "\x41\xff\xe7", 3); break;
  }
}

ELF_DEF void gen_call_r_64(Bytes *s, Register r) {
  switch (r) {
  case RAX: append_bytes(s, "\xff\xd0",     2); break;
  case RBX: append_bytes(s, "\xff\xd3",     2); break;
  case RCX: append_bytes(s, "\xff\xd1",     2); break;
  case RDX: append_bytes(s, "\xff\xd2",     2); break;
  case RSI: append_bytes(s, "\xff\xd6",     2); break;
  case RDI: append_bytes(s, "\xff\xd7",     2); break;
  case RBP: append_bytes(s, "\xff\xd5",     2); break;
  case RSP: append_bytes(s, "\xff\xd4",     2); break;
  case R8:  append_bytes(s, "\x41\xff\xd0", 3); break;
  case R9:  append_bytes(s, "\x41\xff\xd1", 3); break;
  case R10: append_bytes(s, "\x41\xff\xd2", 3); break;
  case R11: append_bytes(s, "\x41\xff\xd3", 3); break;
  case R12: append_bytes(s, "\x41\xff\xd4", 3); break;
  case R13: append_bytes(s, "\x41\xff\xd5", 3); break;
  case R14: append_bytes(s, "\x41\xff\xd6", 3); break;
  case R15: append_bytes(s, "\x41\xff\xd7", 3); break;
  }
}

// ************************* 32-bits *************************
ELF_DEF void gen_add_32_r_imm_short_form(Bytes *s, Register r, char add) {
  switch (r) {
  case EAX:  append_bytes(s, "\x83\xc0",     2); break;
  case EBX:  append_bytes(s, "\x83\xc3",     2); break;
  case ECX:  append_bytes(s, "\x83\xc1",     2); break;
  case EDX:  append_bytes(s, "\x83\xc2",     2); break;
  case ESI:  append_bytes(s, "\x83\xc6",     2); break;
  case EDI:  append_bytes(s, "\x83\xc7",     2); break;
  case EBP:  append_bytes(s, "\x83\xc5",     2); break;
  case ESP:  append_bytes(s, "\x83\xc4",     2); break;
  case R8D:  append_bytes(s, "\x41\x83\xc0", 3); break;
  case R9D:  append_bytes(s, "\x41\x83\xc1", 3); break;
  case R10D: append_bytes(s, "\x41\x83\xc2", 3); break;
  case R11D: append_bytes(s, "\x41\x83\xc3", 3); break;
  case R12D: append_bytes(s, "\x41\x83\xc4", 3); break;
  case R13D: append_bytes(s, "\x41\x83\xc5", 3); break;
  case R14D: append_bytes(s, "\x41\x83\xc6", 3); break;
  case R15D: append_bytes(s, "\x41\x83\xc7", 3); break;
  }

  da_append(s, add);
}

ELF_DEF void gen_add_32_r_imm_long_form(Bytes *s, Register r, size_t add) {
  switch (r) {
  case EAX: da_append(s,    0x05);               break;
  case EBX: append_bytes(s, "\x81\xc3",      2); break;
  case ECX: append_bytes(s, "\x81\xc1",      2); break;
  case EDX: append_bytes(s, "\x81\xc2",      2); break;
  case ESI: append_bytes(s, "\x81\xc6",      2); break;
  case EDI: append_bytes(s, "\x81\xc7",      2); break;
  case EBP: append_bytes(s, "\x81\xc5",      2); break;
  case ESP: append_bytes(s, "\x81\xc4",      2); break;
  case R8D: append_bytes(s, "\x41\x81\xc0",  3); break;
  case R9D: append_bytes(s, "\x41\x81\xc1",  3); break;
  case R10D: append_bytes(s, "\x41\x81\xc2", 3); break;
  case R11D: append_bytes(s, "\x41\x81\xc3", 3); break;
  case R12D: append_bytes(s, "\x41\x81\xc4", 3); break;
  case R13D: append_bytes(s, "\x41\x81\xc5", 3); break;
  case R14D: append_bytes(s, "\x41\x81\xc6", 3); break;
  case R15D: append_bytes(s, "\x41\x81\xc7", 3); break;
  }

  gen_little_endian(s, add, 4);
}

ELF_DEF void gen_sub_32_short_form(Bytes *s, Register r, char sub) {
  switch (r) {
  case EAX: append_bytes(s, "\x83\xe8",      2); break;
  case EBX: append_bytes(s, "\x83\xeb",      2); break;
  case ECX: append_bytes(s, "\x83\xe9",      2); break;
  case EDX: append_bytes(s, "\x83\xea",      2); break;
  case ESI: append_bytes(s, "\x83\xee",      2); break;
  case EDI: append_bytes(s, "\x83\xef",      2); break;
  case EBP: append_bytes(s, "\x83\xed",      2); break;
  case ESP: append_bytes(s, "\x83\xec",      2); break;
  case R8D: append_bytes(s, "\x41\x83\xe8",  3); break;
  case R9D: append_bytes(s, "\x41\x83\xe9",  3); break;
  case R10D: append_bytes(s, "\x41\x83\xea", 3); break;
  case R11D: append_bytes(s, "\x41\x83\xeb", 3); break;
  case R12D: append_bytes(s, "\x41\x83\xec", 3); break;
  case R13D: append_bytes(s, "\x41\x83\xed", 3); break;
  case R14D: append_bytes(s, "\x41\x83\xee", 3); break;
  case R15D: append_bytes(s, "\x41\x83\xef", 3); break;
  }

  da_append(s, sub);
}

ELF_DEF void gen_sub_32_long_form(Bytes *s, Register r, size_t sub) {
  switch (r) {
  case EAX:  da_append(s,    0x2d);              break;
  case EBX:  append_bytes(s, "\x81\xeb",     2); break;
  case ECX:  append_bytes(s, "\x81\xe9",     2); break;
  case EDX:  append_bytes(s, "\x81\xea",     2); break;
  case ESI:  append_bytes(s, "\x81\xee",     2); break;
  case EDI:  append_bytes(s, "\x81\xef",     2); break;
  case EBP:  append_bytes(s, "\x81\xed",     2); break;
  case ESP:  append_bytes(s, "\x81\xec",     2); break;
  case R8D:  append_bytes(s, "\x41\x81\xe8", 3); break;
  case R9D:  append_bytes(s, "\x41\x81\xe9", 3); break;
  case R10D: append_bytes(s, "\x41\x81\xea", 3); break;
  case R11D: append_bytes(s, "\x41\x81\xeb", 3); break;
  case R12D: append_bytes(s, "\x41\x81\xec", 3); break;
  case R13D: append_bytes(s, "\x41\x81\xed", 3); break;
  case R14D: append_bytes(s, "\x41\x81\xee", 3); break;
  case R15D: append_bytes(s, "\x41\x81\xef", 3); break;
  }

  gen_little_endian(s, sub, 4);
}

ELF_DEF void gen_inc_32(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xff\xc0",     2); break;
  case EBX:  append_bytes(s, "\xff\xc3",     2); break;
  case ECX:  append_bytes(s, "\xff\xc1",     2); break;
  case EDX:  append_bytes(s, "\xff\xc2",     2); break;
  case ESI:  append_bytes(s, "\xff\xc6",     2); break;
  case EDI:  append_bytes(s, "\xff\xc7",     2); break;
  case EBP:  append_bytes(s, "\xff\xc5",     2); break;
  case ESP:  append_bytes(s, "\xff\xc4",     2); break;
  case R8D:  append_bytes(s, "\x41\xff\xc0", 3); break;
  case R9D:  append_bytes(s, "\x41\xff\xc1", 3); break;
  case R10D: append_bytes(s, "\x41\xff\xc2", 3); break;
  case R11D: append_bytes(s, "\x41\xff\xc3", 3); break;
  case R12D: append_bytes(s, "\x41\xff\xc4", 3); break;
  case R13D: append_bytes(s, "\x41\xff\xc5", 3); break;
  case R14D: append_bytes(s, "\x41\xff\xc6", 3); break;
  case R15D: append_bytes(s, "\x41\xff\xc7", 3); break;
  }
}

ELF_DEF void gen_dec_32(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xff\xc8",     2); break;
  case EBX:  append_bytes(s, "\xff\xcb",     2); break;
  case ECX:  append_bytes(s, "\xff\xc9",     2); break;
  case EDX:  append_bytes(s, "\xff\xca",     2); break;
  case ESI:  append_bytes(s, "\xff\xce",     2); break;
  case EDI:  append_bytes(s, "\xff\xcf",     2); break;
  case EBP:  append_bytes(s, "\xff\xcd",     2); break;
  case ESP:  append_bytes(s, "\xff\xcc",     2); break;
  case R8D:  append_bytes(s, "\x41\xff\xc8", 3); break;
  case R9D:  append_bytes(s, "\x41\xff\xc9", 3); break;
  case R10D: append_bytes(s, "\x41\xff\xca", 3); break;
  case R11D: append_bytes(s, "\x41\xff\xcb", 3); break;
  case R12D: append_bytes(s, "\x41\xff\xcc", 3); break;
  case R13D: append_bytes(s, "\x41\xff\xcd", 3); break;
  case R14D: append_bytes(s, "\x41\xff\xce", 3); break;
  case R15D: append_bytes(s, "\x41\xff\xcf", 3); break;
  }
}

ELF_DEF void gen_imul_32_short_form(Bytes *s, Register r, char mul) {
  switch (r) {
  case EAX:  append_bytes(s, "\x6b\xc0",     2); break;
  case EBX:  append_bytes(s, "\x6b\xdb",     2); break;
  case ECX:  append_bytes(s, "\x6b\xc9",     2); break;
  case EDX:  append_bytes(s, "\x6b\xd2",     2); break;
  case ESI:  append_bytes(s, "\x6b\xf6",     2); break;
  case EDI:  append_bytes(s, "\x6b\xff",     2); break;
  case EBP:  append_bytes(s, "\x6b\xed",     2); break;
  case ESP:  append_bytes(s, "\x6b\xe4",     2); break;
  case R8D:  append_bytes(s, "\x45\x6b\xc0", 3); break;
  case R9D:  append_bytes(s, "\x45\x6b\xc9", 3); break;
  case R10D: append_bytes(s, "\x45\x6b\xd2", 3); break;
  case R11D: append_bytes(s, "\x45\x6b\xdb", 3); break;
  case R12D: append_bytes(s, "\x45\x6b\xe4", 3); break;
  case R13D: append_bytes(s, "\x45\x6b\xed", 3); break;
  case R14D: append_bytes(s, "\x45\x6b\xf6", 3); break;
  case R15D: append_bytes(s, "\x45\x6b\xff", 3); break;
  }

  da_append(s, mul);
}

ELF_DEF void gen_imul_32_long_form(Bytes *s, Register r, size_t mul) {
  switch (r) {
  case EAX:  append_bytes(s, "\x69\xc0",     2); break;
  case EBX:  append_bytes(s, "\x69\xdb",     2); break;
  case ECX:  append_bytes(s, "\x69\xc9",     2); break;
  case EDX:  append_bytes(s, "\x69\xd2",     2); break;
  case ESI:  append_bytes(s, "\x69\xf6",     2); break;
  case EDI:  append_bytes(s, "\x69\xff",     2); break;
  case EBP:  append_bytes(s, "\x69\xed",     2); break;
  case ESP:  append_bytes(s, "\x69\xe4",     2); break;
  case R8D:  append_bytes(s, "\x45\x69\xc0", 3); break;
  case R9D:  append_bytes(s, "\x45\x69\xc9", 3); break;
  case R10D: append_bytes(s, "\x45\x69\xd2", 3); break;
  case R11D: append_bytes(s, "\x45\x69\xdb", 3); break;
  case R12D: append_bytes(s, "\x45\x69\xe4", 3); break;
  case R13D: append_bytes(s, "\x45\x69\xed", 3); break;
  case R14D: append_bytes(s, "\x45\x69\xf6", 3); break;
  case R15D: append_bytes(s, "\x45\x69\xff", 3); break;
  }

  gen_little_endian(s, mul, 4);
}

ELF_DEF void gen_div_32(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xf7\xf0",     2); break;
  case EBX:  append_bytes(s, "\xf7\xf3",     2); break;
  case ECX:  append_bytes(s, "\xf7\xf1",     2); break;
  case EDX:  append_bytes(s, "\xf7\xf2",     2); break;
  case ESI:  append_bytes(s, "\xf7\xf6",     2); break;
  case EDI:  append_bytes(s, "\xf7\xf7",     2); break;
  case EBP:  append_bytes(s, "\xf7\xf5",     2); break;
  case ESP:  append_bytes(s, "\xf7\xf4",     2); break;
  case R8D:  append_bytes(s, "\x41\xf7\xf0", 3); break;
  case R9D:  append_bytes(s, "\x41\xf7\xf1", 3); break;
  case R10D: append_bytes(s, "\x41\xf7\xf2", 3); break;
  case R11D: append_bytes(s, "\x41\xf7\xf3", 3); break;
  case R12D: append_bytes(s, "\x41\xf7\xf4", 3); break;
  case R13D: append_bytes(s, "\x41\xf7\xf5", 3); break;
  case R14D: append_bytes(s, "\x41\xf7\xf6", 3); break;
  case R15D: append_bytes(s, "\x41\xf7\xf7", 3); break;
  }
}

ELF_DEF void gen_and_32_r_imm_short_form(Bytes *s, Register r, char and) {
  switch (r) {
  case EAX:  append_bytes(s, "\x83\xe0",     2); break;
  case EBX:  append_bytes(s, "\x83\xe3",     2); break;
  case ECX:  append_bytes(s, "\x83\xe1",     2); break;
  case EDX:  append_bytes(s, "\x83\xe2",     2); break;
  case ESI:  append_bytes(s, "\x83\xe6",     2); break;
  case EDI:  append_bytes(s, "\x83\xe7",     2); break;
  case EBP:  append_bytes(s, "\x83\xe5",     2); break;
  case ESP:  append_bytes(s, "\x83\xe4",     2); break;
  case R8D:  append_bytes(s, "\x41\x83\xe0", 3); break;
  case R9D:  append_bytes(s, "\x41\x83\xe1", 3); break;
  case R10D: append_bytes(s, "\x41\x83\xe2", 3); break;
  case R11D: append_bytes(s, "\x41\x83\xe3", 3); break;
  case R12D: append_bytes(s, "\x41\x83\xe4", 3); break;
  case R13D: append_bytes(s, "\x41\x83\xe5", 3); break;
  case R14D: append_bytes(s, "\x41\x83\xe6", 3); break;
  case R15D: append_bytes(s, "\x41\x83\xe7", 3); break;
  }

  da_append(s, and);
}

ELF_DEF void gen_and_32_r_imm_long_form(Bytes *s, Register r, size_t and) {
  switch (r) {
  case EAX:  da_append(s,    0x25);              break;
  case EBX:  append_bytes(s, "\x81\xe3",     2); break;
  case ECX:  append_bytes(s, "\x81\xe1",     2); break;
  case EDX:  append_bytes(s, "\x81\xe2",     2); break;
  case ESI:  append_bytes(s, "\x81\xe6",     2); break;
  case EDI:  append_bytes(s, "\x81\xe7",     2); break;
  case EBP:  append_bytes(s, "\x81\xe5",     2); break;
  case ESP:  append_bytes(s, "\x81\xe4",     2); break;
  case R8D:  append_bytes(s, "\x41\x81\xe0", 3); break;
  case R9D:  append_bytes(s, "\x41\x81\xe1", 3); break;
  case R10D: append_bytes(s, "\x41\x81\xe2", 3); break;
  case R11D: append_bytes(s, "\x41\x81\xe3", 3); break;
  case R12D: append_bytes(s, "\x41\x81\xe4", 3); break;
  case R13D: append_bytes(s, "\x41\x81\xe5", 3); break;
  case R14D: append_bytes(s, "\x41\x81\xe6", 3); break;
  case R15D: append_bytes(s, "\x41\x81\xe7", 3); break;
  }

  gen_little_endian(s, and, 4);
}

ELF_DEF void gen_or_32_r_imm_short_form(Bytes *s, Register r, char or) {
  switch (r) {
  case EAX:  append_bytes(s, "\x83\xc8",     2); break;
  case EBX:  append_bytes(s, "\x83\xcb",     2); break;
  case ECX:  append_bytes(s, "\x83\xc9",     2); break;
  case EDX:  append_bytes(s, "\x83\xca",     2); break;
  case ESI:  append_bytes(s, "\x83\xce",     2); break;
  case EDI:  append_bytes(s, "\x83\xcf",     2); break;
  case EBP:  append_bytes(s, "\x83\xcd",     2); break;
  case ESP:  append_bytes(s, "\x83\xcc",     2); break;
  case R8D:  append_bytes(s, "\x41\x83\xc8", 3); break;
  case R9D:  append_bytes(s, "\x41\x83\xc9", 3); break;
  case R10D: append_bytes(s, "\x41\x83\xca", 3); break;
  case R11D: append_bytes(s, "\x41\x83\xcb", 3); break;
  case R12D: append_bytes(s, "\x41\x83\xcc", 3); break;
  case R13D: append_bytes(s, "\x41\x83\xcd", 3); break;
  case R14D: append_bytes(s, "\x41\x83\xce", 3); break;
  case R15D: append_bytes(s, "\x41\x83\xcf", 3); break;
  }

  da_append(s, or);
}

ELF_DEF void gen_or_32_r_imm_long_form(Bytes *s, Register r, size_t or) {
  switch (r) {
  case EAX:  da_append(s,    0x0d);              break;
  case EBX:  append_bytes(s, "\x81\xcb",     2); break;
  case ECX:  append_bytes(s, "\x81\xc9",     2); break;
  case EDX:  append_bytes(s, "\x81\xca",     2); break;
  case ESI:  append_bytes(s, "\x81\xce",     2); break;
  case EDI:  append_bytes(s, "\x81\xcf",     2); break;
  case EBP:  append_bytes(s, "\x81\xcd",     2); break;
  case ESP:  append_bytes(s, "\x81\xcc",     2); break;
  case R8D:  append_bytes(s, "\x41\x81\xc8", 3); break;
  case R9D:  append_bytes(s, "\x41\x81\xc9", 3); break;
  case R10D: append_bytes(s, "\x41\x81\xca", 3); break;
  case R11D: append_bytes(s, "\x41\x81\xcb", 3); break;
  case R12D: append_bytes(s, "\x41\x81\xcc", 3); break;
  case R13D: append_bytes(s, "\x41\x81\xcd", 3); break;
  case R14D: append_bytes(s, "\x41\x81\xce", 3); break;
  case R15D: append_bytes(s, "\x41\x81\xcf", 3); break;
  }

  gen_little_endian(s, or, 4);
}

ELF_DEF void gen_not_32(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xf7\xd0",     2); break;
  case EBX:  append_bytes(s, "\xf7\xd3",     2); break;
  case ECX:  append_bytes(s, "\xf7\xd1",     2); break;
  case EDX:  append_bytes(s, "\xf7\xd2",     2); break;
  case ESI:  append_bytes(s, "\xf7\xd6",     2); break;
  case EDI:  append_bytes(s, "\xf7\xd7",     2); break;
  case EBP:  append_bytes(s, "\xf7\xd5",     2); break;
  case ESP:  append_bytes(s, "\xf7\xd4",     2); break;
  case R8D:  append_bytes(s, "\x41\xf7\xd0", 3); break;
  case R9D:  append_bytes(s, "\x41\xf7\xd1", 3); break;
  case R10D: append_bytes(s, "\x41\xf7\xd2", 3); break;
  case R11D: append_bytes(s, "\x41\xf7\xd3", 3); break;
  case R12D: append_bytes(s, "\x41\xf7\xd4", 3); break;
  case R13D: append_bytes(s, "\x41\xf7\xd5", 3); break;
  case R14D: append_bytes(s, "\x41\xf7\xd6", 3); break;
  case R15D: append_bytes(s, "\x41\xf7\xd7", 3); break;
  }
}

ELF_DEF void gen_shr_32_r_1(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xd1\xe8",     2); break;
  case EBX:  append_bytes(s, "\xd1\xeb",     2); break;
  case ECX:  append_bytes(s, "\xd1\xe9",     2); break;
  case EDX:  append_bytes(s, "\xd1\xea",     2); break;
  case ESI:  append_bytes(s, "\xd1\xee",     2); break;
  case EDI:  append_bytes(s, "\xd1\xef",     2); break;
  case EBP:  append_bytes(s, "\xd1\xed",     2); break;
  case ESP:  append_bytes(s, "\xd1\xec",     2); break;
  case R8D:  append_bytes(s, "\x41\xd1\xe8", 3); break;
  case R9D:  append_bytes(s, "\x41\xd1\xe9", 3); break;
  case R10D: append_bytes(s, "\x41\xd1\xea", 3); break;
  case R11D: append_bytes(s, "\x41\xd1\xeb", 3); break;
  case R12D: append_bytes(s, "\x41\xd1\xec", 3); break;
  case R13D: append_bytes(s, "\x41\xd1\xed", 3); break;
  case R14D: append_bytes(s, "\x41\xd1\xee", 3); break;
  case R15D: append_bytes(s, "\x41\xd1\xef", 3); break;
  }
}

ELF_DEF void gen_shr_32_r_imm(Bytes *s, Register r, char shr) {
  switch (r) {
  case EAX:  append_bytes(s, "\xc1\xe8",     2); break;
  case EBX:  append_bytes(s, "\xc1\xeb",     2); break;
  case ECX:  append_bytes(s, "\xc1\xe9",     2); break;
  case EDX:  append_bytes(s, "\xc1\xea",     2); break;
  case ESI:  append_bytes(s, "\xc1\xee",     2); break;
  case EDI:  append_bytes(s, "\xc1\xef",     2); break;
  case EBP:  append_bytes(s, "\xc1\xed",     2); break;
  case ESP:  append_bytes(s, "\xc1\xec",     2); break;
  case R8D:  append_bytes(s, "\x41\xc1\xe8", 3); break;
  case R9D:  append_bytes(s, "\x41\xc1\xe9", 3); break;
  case R10D: append_bytes(s, "\x41\xc1\xea", 3); break;
  case R11D: append_bytes(s, "\x41\xc1\xeb", 3); break;
  case R12D: append_bytes(s, "\x41\xc1\xec", 3); break;
  case R13D: append_bytes(s, "\x41\xc1\xed", 3); break;
  case R14D: append_bytes(s, "\x41\xc1\xee", 3); break;
  case R15D: append_bytes(s, "\x41\xc1\xef", 3); break;
  }

  da_append(s, shr);
}

ELF_DEF void gen_shr_32_r_cl(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xd3\xe8",     2); break;
  case EBX:  append_bytes(s, "\xd3\xeb",     2); break;
  case ECX:  append_bytes(s, "\xd3\xe9",     2); break;
  case EDX:  append_bytes(s, "\xd3\xea",     2); break;
  case ESI:  append_bytes(s, "\xd3\xee",     2); break;
  case EDI:  append_bytes(s, "\xd3\xef",     2); break;
  case EBP:  append_bytes(s, "\xd3\xed",     2); break;
  case ESP:  append_bytes(s, "\xd3\xec",     2); break;
  case R8D:  append_bytes(s, "\x41\xd3\xe8", 3); break;
  case R9D:  append_bytes(s, "\x41\xd3\xe9", 3); break;
  case R10D: append_bytes(s, "\x41\xd3\xea", 3); break;
  case R11D: append_bytes(s, "\x41\xd3\xeb", 3); break;
  case R12D: append_bytes(s, "\x41\xd3\xec", 3); break;
  case R13D: append_bytes(s, "\x41\xd3\xed", 3); break;
  case R14D: append_bytes(s, "\x41\xd3\xee", 3); break;
  case R15D: append_bytes(s, "\x41\xd3\xef", 3); break;
  }
}

ELF_DEF void gen_shl_32_r_1(Bytes *s, Register r) {
  switch (r) {
  case EAX:   append_bytes(s, "\xd1\xe0",     2); break;
  case EBX:   append_bytes(s, "\xd1\xe3",     2); break;
  case ECX:   append_bytes(s, "\xd1\xe1",     2); break;
  case EDX:   append_bytes(s, "\xd1\xe2",     2); break;
  case ESI:   append_bytes(s, "\xd1\xe6",     2); break;
  case EDI:   append_bytes(s, "\xd1\xe7",     2); break;
  case EBP:   append_bytes(s, "\xd1\xe5",     2); break;
  case ESP:   append_bytes(s, "\xd1\xe4",     2); break;
  case R8D:   append_bytes(s, "\x41\xd1\xe0", 3); break;
  case R9D:   append_bytes(s, "\x41\xd1\xe1", 3); break;
  case R10D:  append_bytes(s, "\x41\xd1\xe2", 3); break;
  case R11D:  append_bytes(s, "\x41\xd1\xe3", 3); break;
  case R12D:  append_bytes(s, "\x41\xd1\xe4", 3); break;
  case R13D:  append_bytes(s, "\x41\xd1\xe5", 3); break;
  case R14D:  append_bytes(s, "\x41\xd1\xe6", 3); break;
  case R15D:  append_bytes(s, "\x41\xd1\xe7", 3); break;
  }
}

ELF_DEF void gen_shl_32_r_imm(Bytes *s, Register r, char shl) {
  switch (r) {
  case EAX:  append_bytes(s, "\xc1\xe0",     2); break;
  case EBX:  append_bytes(s, "\xc1\xe3",     2); break;
  case ECX:  append_bytes(s, "\xc1\xe1",     2); break;
  case EDX:  append_bytes(s, "\xc1\xe2",     2); break;
  case ESI:  append_bytes(s, "\xc1\xe6",     2); break;
  case EDI:  append_bytes(s, "\xc1\xe7",     2); break;
  case EBP:  append_bytes(s, "\xc1\xe5",     2); break;
  case ESP:  append_bytes(s, "\xc1\xe4",     2); break;
  case R8D:  append_bytes(s, "\x41\xc1\xe0", 3); break;
  case R9D:  append_bytes(s, "\x41\xc1\xe1", 3); break;
  case R10D: append_bytes(s, "\x41\xc1\xe2", 3); break;
  case R11D: append_bytes(s, "\x41\xc1\xe3", 3); break;
  case R12D: append_bytes(s, "\x41\xc1\xe4", 3); break;
  case R13D: append_bytes(s, "\x41\xc1\xe5", 3); break;
  case R14D: append_bytes(s, "\x41\xc1\xe6", 3); break;
  case R15D: append_bytes(s, "\x41\xc1\xe7", 3); break;
  }

  da_append(s, shl);
}

ELF_DEF void gen_shl_32_r_cl(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xd3\xe0",     2); break;
  case EBX:  append_bytes(s, "\xd3\xe3",     2); break;
  case ECX:  append_bytes(s, "\xd3\xe1",     2); break;
  case EDX:  append_bytes(s, "\xd3\xe2",     2); break;
  case ESI:  append_bytes(s, "\xd3\xe6",     2); break;
  case EDI:  append_bytes(s, "\xd3\xe7",     2); break;
  case EBP:  append_bytes(s, "\xd3\xe5",     2); break;
  case ESP:  append_bytes(s, "\xd3\xe4",     2); break;
  case R8D:  append_bytes(s, "\x41\xd3\xe0", 3); break;
  case R9D:  append_bytes(s, "\x41\xd3\xe1", 3); break;
  case R10D: append_bytes(s, "\x41\xd3\xe2", 3); break;
  case R11D: append_bytes(s, "\x41\xd3\xe3", 3); break;
  case R12D: append_bytes(s, "\x41\xd3\xe4", 3); break;
  case R13D: append_bytes(s, "\x41\xd3\xe5", 3); break;
  case R14D: append_bytes(s, "\x41\xd3\xe6", 3); break;
  case R15D: append_bytes(s, "\x41\xd3\xe7", 3); break;
  }
}

ELF_DEF void gen_sar_32_r_1(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s,"\xd1\xf8",     2); break;
  case EBX:  append_bytes(s,"\xd1\xfb",     2); break;
  case ECX:  append_bytes(s,"\xd1\xf9",     2); break;
  case EDX:  append_bytes(s,"\xd1\xfa",     2); break;
  case ESI:  append_bytes(s,"\xd1\xfe",     2); break;
  case EDI:  append_bytes(s,"\xd1\xff",     2); break;
  case EBP:  append_bytes(s,"\xd1\xfd",     2); break;
  case ESP:  append_bytes(s,"\xd1\xfc",     2); break;
  case R8D:  append_bytes(s,"\x41\xd1\xf8", 3); break;
  case R9D:  append_bytes(s,"\x41\xd1\xf9", 3); break;
  case R10D: append_bytes(s,"\x41\xd1\xfa", 3); break;
  case R11D: append_bytes(s,"\x41\xd1\xfb", 3); break;
  case R12D: append_bytes(s,"\x41\xd1\xfc", 3); break;
  case R13D: append_bytes(s,"\x41\xd1\xfd", 3); break;
  case R14D: append_bytes(s,"\x41\xd1\xfe", 3); break;
  case R15D: append_bytes(s,"\x41\xd1\xff", 3); break;
  }
}

ELF_DEF void gen_sar_32_r_imm(Bytes *s, Register r, char sar) {
  switch (r) {
  case EAX:  append_bytes(s, "\xc1\xf8\x0a",     3); break;
  case EBX:  append_bytes(s, "\xc1\xfb\x0a",     3); break;
  case ECX:  append_bytes(s, "\xc1\xf9\x0a",     3); break;
  case EDX:  append_bytes(s, "\xc1\xfa\x0a",     3); break;
  case ESI:  append_bytes(s, "\xc1\xfe\x0a",     3); break;
  case EDI:  append_bytes(s, "\xc1\xff\x0a",     3); break;
  case EBP:  append_bytes(s, "\xc1\xfd\x0a",     3); break;
  case ESP:  append_bytes(s, "\xc1\xfc\x0a",     3); break;
  case R8D:  append_bytes(s, "\x41\xc1\xf8\x0a", 4); break;
  case R9D:  append_bytes(s, "\x41\xc1\xf9\x0a", 4); break;
  case R10D: append_bytes(s, "\x41\xc1\xfa\x0a", 4); break;
  case R11D: append_bytes(s, "\x41\xc1\xfb\x0a", 4); break;
  case R12D: append_bytes(s, "\x41\xc1\xfc\x0a", 4); break;
  case R13D: append_bytes(s, "\x41\xc1\xfd\x0a", 4); break;
  case R14D: append_bytes(s, "\x41\xc1\xfe\x0a", 4); break;
  case R15D: append_bytes(s, "\x41\xc1\xff\x0a", 4); break;
  }

  da_append(s, sar);
}

ELF_DEF void gen_sar_32_r_cl(Bytes *s, Register r) {
  switch (r) {
  case EAX:  append_bytes(s, "\xd3\xf8",     2); break;
  case EBX:  append_bytes(s, "\xd3\xfb",     2); break;
  case ECX:  append_bytes(s, "\xd3\xf9",     2); break;
  case EDX:  append_bytes(s, "\xd3\xfa",     2); break;
  case ESI:  append_bytes(s, "\xd3\xfe",     2); break;
  case EDI:  append_bytes(s, "\xd3\xff",     2); break;
  case EBP:  append_bytes(s, "\xd3\xfd",     2); break;
  case ESP:  append_bytes(s, "\xd3\xfc",     2); break;
  case R8D:  append_bytes(s, "\x41\xd3\xf8", 3); break;
  case R9D:  append_bytes(s, "\x41\xd3\xf9", 3); break;
  case R10D: append_bytes(s, "\x41\xd3\xfa", 3); break;
  case R11D: append_bytes(s, "\x41\xd3\xfb", 3); break;
  case R12D: append_bytes(s, "\x41\xd3\xfc", 3); break;
  case R13D: append_bytes(s, "\x41\xd3\xfd", 3); break;
  case R14D: append_bytes(s, "\x41\xd3\xfe", 3); break;
  case R15D: append_bytes(s, "\x41\xd3\xff", 3); break;
  }
}

ELF_DEF void gen_cmp_32_r_imm_short_form(Bytes *s, Register r, char cmp) {
  switch (r) {
  case EAX:  append_bytes(s, "\x83\xf8",     2); break;
  case EBX:  append_bytes(s, "\x83\xfb",     2); break;
  case ECX:  append_bytes(s, "\x83\xf9",     2); break;
  case EDX:  append_bytes(s, "\x83\xfa",     2); break;
  case ESI:  append_bytes(s, "\x83\xfe",     2); break;
  case EDI:  append_bytes(s, "\x83\xff",     2); break;
  case EBP:  append_bytes(s, "\x83\xfd",     2); break;
  case ESP:  append_bytes(s, "\x83\xfc",     2); break;
  case R8D:  append_bytes(s, "\x41\x83\xf8", 3); break;
  case R9D:  append_bytes(s, "\x41\x83\xf9", 3); break;
  case R10D: append_bytes(s, "\x41\x83\xfa", 3); break;
  case R11D: append_bytes(s, "\x41\x83\xfb", 3); break;
  case R12D: append_bytes(s, "\x41\x83\xfc", 3); break;
  case R13D: append_bytes(s, "\x41\x83\xfd", 3); break;
  case R14D: append_bytes(s, "\x41\x83\xfe", 3); break;
  case R15D: append_bytes(s, "\x41\x83\xff", 3); break;
  }

  da_append(s, cmp);
}

ELF_DEF void gen_cmp_32_r_imm_long_form(Bytes *s, Register r, size_t cmp) {
  switch (r) {
  case EAX:  da_append(s,    0x3d);              break;
  case EBX:  append_bytes(s, "\x81\xfb",     2); break;
  case ECX:  append_bytes(s, "\x81\xf9",     2); break;
  case EDX:  append_bytes(s, "\x81\xfa",     2); break;
  case ESI:  append_bytes(s, "\x81\xfe",     2); break;
  case EDI:  append_bytes(s, "\x81\xff",     2); break;
  case EBP:  append_bytes(s, "\x81\xfd",     2); break;
  case ESP:  append_bytes(s, "\x81\xfc",     2); break;
  case R8D:  append_bytes(s, "\x41\x81\xf8", 3); break;
  case R9D:  append_bytes(s, "\x41\x81\xf9", 3); break;
  case R10D: append_bytes(s, "\x41\x81\xfa", 3); break;
  case R11D: append_bytes(s, "\x41\x81\xfb", 3); break;
  case R12D: append_bytes(s, "\x41\x81\xfc", 3); break;
  case R13D: append_bytes(s, "\x41\x81\xfd", 3); break;
  case R14D: append_bytes(s, "\x41\x81\xfe", 3); break;
  case R15D: append_bytes(s, "\x41\x81\xff", 3); break;
  }

  gen_little_endian(s, cmp, 4);
}

ELF_DEF void gen_push_32(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_pop_32(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_jmp_r_32(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_call_r_32(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

// ************************* 16-bits *************************
ELF_DEF void gen_add_16_r_imm_short_form(Bytes *s, Register r, char add) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x83\xc0",     3); break;
  case BX:   append_bytes(s, "\x66\x83\xc3",     3); break;
  case CX:   append_bytes(s, "\x66\x83\xc1",     3); break;
  case DX:   append_bytes(s, "\x66\x83\xc2",     3); break;
  case SI:   append_bytes(s, "\x66\x83\xc6",     3); break;
  case DI:   append_bytes(s, "\x66\x83\xc7",     3); break;
  case BP:   append_bytes(s, "\x66\x83\xc5",     3); break;
  case SP:   append_bytes(s, "\x66\x83\xc4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x83\xc0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x83\xc1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x83\xc2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x83\xc3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x83\xc4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x83\xc5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x83\xc6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x83\xc7", 4); break;
  }

  da_append(s, add);
}

ELF_DEF void gen_add_16_r_imm_long_form(Bytes *s, Register r, size_t add) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x05",         2); break;
  case BX:   append_bytes(s, "\x66\x81\xc3",     3); break;
  case CX:   append_bytes(s, "\x66\x81\xc1",     3); break;
  case DX:   append_bytes(s, "\x66\x81\xc2",     3); break;
  case SI:   append_bytes(s, "\x66\x81\xc6",     3); break;
  case DI:   append_bytes(s, "\x66\x81\xc7",     3); break;
  case BP:   append_bytes(s, "\x66\x81\xc5",     3); break;
  case SP:   append_bytes(s, "\x66\x81\xc4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x81\xc0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x81\xc1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x81\xc2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x81\xc3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x81\xc4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x81\xc5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x81\xc6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x81\xc7", 4); break;
  }

  gen_little_endian(s, add, 2);
}

ELF_DEF void gen_sub_16_r_imm_short_form(Bytes *s, Register r, char sub) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x83\xe8",     3); break;
  case BX:   append_bytes(s, "\x66\x83\xeb",     3); break;
  case CX:   append_bytes(s, "\x66\x83\xe9",     3); break;
  case DX:   append_bytes(s, "\x66\x83\xea",     3); break;
  case SI:   append_bytes(s, "\x66\x83\xee",     3); break;
  case DI:   append_bytes(s, "\x66\x83\xef",     3); break;
  case BP:   append_bytes(s, "\x66\x83\xed",     3); break;
  case SP:   append_bytes(s, "\x66\x83\xec",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x83\xe8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x83\xe9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x83\xea", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x83\xeb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x83\xec", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x83\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x83\xee", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x83\xef", 4); break;
  }

  da_append(s, sub);
}

ELF_DEF void gen_sub_16_r_imm_long_form(Bytes *s, Register r, size_t sub) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x2d",         2); break;
  case BX:   append_bytes(s, "\x66\x81\xeb",     3); break;
  case CX:   append_bytes(s, "\x66\x81\xe9",     3); break;
  case DX:   append_bytes(s, "\x66\x81\xea",     3); break;
  case SI:   append_bytes(s, "\x66\x81\xee",     3); break;
  case DI:   append_bytes(s, "\x66\x81\xef",     3); break;
  case BP:   append_bytes(s, "\x66\x81\xed",     3); break;
  case SP:   append_bytes(s, "\x66\x81\xec",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x81\xe8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x81\xe9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x81\xea", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x81\xeb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x81\xec", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x81\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x81\xee", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x81\xef", 4); break;
  }

  gen_little_endian(s, sub, 2);
}

ELF_DEF void gen_inc_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xff\xc0",     3); break;
  case BX:   append_bytes(s, "\x66\xff\xc3",     3); break;
  case CX:   append_bytes(s, "\x66\xff\xc1",     3); break;
  case DX:   append_bytes(s, "\x66\xff\xc2",     3); break;
  case SI:   append_bytes(s, "\x66\xff\xc6",     3); break;
  case DI:   append_bytes(s, "\x66\xff\xc7",     3); break;
  case BP:   append_bytes(s, "\x66\xff\xc5",     3); break;
  case SP:   append_bytes(s, "\x66\xff\xc4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xff\xc0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xff\xc1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xff\xc2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xff\xc3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xff\xc4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xff\xc5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xff\xc6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xff\xc7", 4); break;
  }  
}

ELF_DEF void gen_dec_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "66\xff\xc8",       3); break;
  case BX:   append_bytes(s, "66\xff\xcb",       3); break;
  case CX:   append_bytes(s, "66\xff\xc9",       3); break;
  case DX:   append_bytes(s, "66\xff\xca",       3); break;
  case SI:   append_bytes(s, "66\xff\xce",       3); break;
  case DI:   append_bytes(s, "66\xff\xcf",       3); break;
  case BP:   append_bytes(s, "66\xff\xcd",       3); break;
  case SP:   append_bytes(s, "66\xff\xcc",       3); break;
  case R8W:  append_bytes(s, "\x66\x41\xff\xc8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xff\xc9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xff\xca", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xff\xcb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xff\xcc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xff\xcd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xff\xce", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xff\xcf", 4); break;
  }  
}

ELF_DEF void gen_imul_16_r_imm_short_form(Bytes *s, Register r, char mul) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x6b\xc0",     3); break;
  case BX:   append_bytes(s, "\x66\x6b\xdb",     3); break;
  case CX:   append_bytes(s, "\x66\x6b\xc9",     3); break;
  case DX:   append_bytes(s, "\x66\x6b\xd2",     3); break;
  case SI:   append_bytes(s, "\x66\x6b\xf6",     3); break;
  case DI:   append_bytes(s, "\x66\x6b\xff",     3); break;
  case BP:   append_bytes(s, "\x66\x6b\xed",     3); break;
  case SP:   append_bytes(s, "\x66\x6b\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x45\x6b\xc0", 4); break;
  case R9W:  append_bytes(s, "\x66\x45\x6b\xc9", 4); break;
  case R10W: append_bytes(s, "\x66\x45\x6b\xd2", 4); break;
  case R11W: append_bytes(s, "\x66\x45\x6b\xdb", 4); break;
  case R12W: append_bytes(s, "\x66\x45\x6b\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x45\x6b\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x45\x6b\xf6", 4); break;
  case R15W: append_bytes(s, "\x66\x45\x6b\xff", 4); break;
  }

  da_append(s, mul);
}

ELF_DEF void gen_imul_16_r_imm_long_form(Bytes *s, Register r, size_t mul) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x69\xc0",     3); break;
  case BX:   append_bytes(s, "\x66\x69\xdb",     3); break;
  case CX:   append_bytes(s, "\x66\x69\xc9",     3); break;
  case DX:   append_bytes(s, "\x66\x69\xd2",     3); break;
  case SI:   append_bytes(s, "\x66\x69\xf6",     3); break;
  case DI:   append_bytes(s, "\x66\x69\xff",     3); break;
  case BP:   append_bytes(s, "\x66\x69\xed",     3); break;
  case SP:   append_bytes(s, "\x66\x69\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x45\x69\xc0", 4); break;
  case R9W:  append_bytes(s, "\x66\x45\x69\xc9", 4); break;
  case R10W: append_bytes(s, "\x66\x45\x69\xd2", 4); break;
  case R11W: append_bytes(s, "\x66\x45\x69\xdb", 4); break;
  case R12W: append_bytes(s, "\x66\x45\x69\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x45\x69\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x45\x69\xf6", 4); break;
  case R15W: append_bytes(s, "\x66\x45\x69\xff", 4); break;
  }
}

ELF_DEF void gen_div_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xf7\xf0",     3); break;
  case BX:   append_bytes(s, "\x66\xf7\xf3",     3); break;
  case CX:   append_bytes(s, "\x66\xf7\xf1",     3); break;
  case DX:   append_bytes(s, "\x66\xf7\xf2",     3); break;
  case SI:   append_bytes(s, "\x66\xf7\xf6",     3); break;
  case DI:   append_bytes(s, "\x66\xf7\xf7",     3); break;
  case BP:   append_bytes(s, "\x66\xf7\xf5",     3); break;
  case SP:   append_bytes(s, "\x66\xf7\xf4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xf7\xf0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xf7\xf1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xf7\xf2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xf7\xf3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xf7\xf4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xf7\xf5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xf7\xf6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xf7\xf7", 4); break;
  }
}

ELF_DEF void gen_and_16_r_imm_short_form(Bytes *s, Register r, char and) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x83\xe0",     3); break;
  case BX:   append_bytes(s, "\x66\x83\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\x83\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\x83\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\x83\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\x83\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\x83\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\x83\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x83\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x83\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x83\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x83\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x83\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x83\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x83\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x83\xe7", 4); break;
  }

  da_append(s, and);
}

ELF_DEF void gen_and_16_r_imm_long_form(Bytes *s, Register r, size_t and) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x25",         2); break;
  case BX:   append_bytes(s, "\x66\x81\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\x81\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\x81\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\x81\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\x81\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\x81\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\x81\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x81\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x81\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x81\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x81\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x81\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x81\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x81\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x81\xe7", 4); break;
  }

  gen_little_endian(s, and, 2);
}

ELF_DEF void gen_or_16_r_imm_short_form(Bytes *s, Register r, char or) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x83\xc8",     3); break;
  case BX:   append_bytes(s, "\x66\x83\xcb",     3); break;
  case CX:   append_bytes(s, "\x66\x83\xc9",     3); break;
  case DX:   append_bytes(s, "\x66\x83\xca",     3); break;
  case SI:   append_bytes(s, "\x66\x83\xce",     3); break;
  case DI:   append_bytes(s, "\x66\x83\xcf",     3); break;
  case BP:   append_bytes(s, "\x66\x83\xcd",     3); break;
  case SP:   append_bytes(s, "\x66\x83\xcc",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x83\xc8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x83\xc9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x83\xca", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x83\xcb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x83\xcc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x83\xcd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x83\xce", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x83\xcf", 4); break;
  }

  da_append(s, or);
}

ELF_DEF void gen_or_16_r_imm_long_form(Bytes *s, Register r, size_t or) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x0d",         2); break;
  case BX:   append_bytes(s, "\x66\x81\xcb",     3); break;
  case CX:   append_bytes(s, "\x66\x81\xc9",     3); break;
  case DX:   append_bytes(s, "\x66\x81\xca",     3); break;
  case SI:   append_bytes(s, "\x66\x81\xce",     3); break;
  case DI:   append_bytes(s, "\x66\x81\xcf",     3); break;
  case BP:   append_bytes(s, "\x66\x81\xcd",     3); break;
  case SP:   append_bytes(s, "\x66\x81\xcc",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x81\xc8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x81\xc9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x81\xca", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x81\xcb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x81\xcc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x81\xcd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x81\xce", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x81\xcf", 4); break;
  }

  gen_little_endian(s, or, 2);
}

ELF_DEF void gen_not_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xf7\xd0",     3); break;
  case BX:   append_bytes(s, "\x66\xf7\xd3",     3); break;
  case CX:   append_bytes(s, "\x66\xf7\xd1",     3); break;
  case DX:   append_bytes(s, "\x66\xf7\xd2",     3); break;
  case SI:   append_bytes(s, "\x66\xf7\xd6",     3); break;
  case DI:   append_bytes(s, "\x66\xf7\xd7",     3); break;
  case BP:   append_bytes(s, "\x66\xf7\xd5",     3); break;
  case SP:   append_bytes(s, "\x66\xf7\xd4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xf7\xd0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xf7\xd1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xf7\xd2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xf7\xd3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xf7\xd4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xf7\xd5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xf7\xd6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xf7\xd7", 4); break;
  }
}

ELF_DEF void gen_shr_16_r_1(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xd1\xe8",     3); break;
  case BX:   append_bytes(s, "\x66\xd1\xeb",     3); break;
  case CX:   append_bytes(s, "\x66\xd1\xe9",     3); break;
  case DX:   append_bytes(s, "\x66\xd1\xea",     3); break;
  case SI:   append_bytes(s, "\x66\xd1\xee",     3); break;
  case DI:   append_bytes(s, "\x66\xd1\xef",     3); break;
  case BP:   append_bytes(s, "\x66\xd1\xed",     3); break;
  case SP:   append_bytes(s, "\x66\xd1\xec",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xd1\xe8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xd1\xe9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xd1\xea", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xd1\xeb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xd1\xec", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xd1\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xd1\xee", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xd1\xef", 4); break;
  }
}

ELF_DEF void gen_shr_16_r_imm(Bytes *s, Register r, char shr) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xc1\xe8",     3); break;
  case BX:   append_bytes(s, "\x66\xc1\xeb",     3); break;
  case CX:   append_bytes(s, "\x66\xc1\xe9",     3); break;
  case DX:   append_bytes(s, "\x66\xc1\xea",     3); break;
  case SI:   append_bytes(s, "\x66\xc1\xee",     3); break;
  case DI:   append_bytes(s, "\x66\xc1\xef",     3); break;
  case BP:   append_bytes(s, "\x66\xc1\xed",     3); break;
  case SP:   append_bytes(s, "\x66\xc1\xec",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xc1\xe8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xc1\xe9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xc1\xea", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xc1\xeb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xc1\xec", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xc1\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xc1\xee", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xc1\xef", 4); break;
  }

  da_append(s, shr);
}

ELF_DEF void gen_shr_16_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xd3\xe8",     3); break;
  case BX:   append_bytes(s, "\x66\xd3\xeb",     3); break;
  case CX:   append_bytes(s, "\x66\xd3\xe9",     3); break;
  case DX:   append_bytes(s, "\x66\xd3\xea",     3); break;
  case SI:   append_bytes(s, "\x66\xd3\xee",     3); break;
  case DI:   append_bytes(s, "\x66\xd3\xef",     3); break;
  case BP:   append_bytes(s, "\x66\xd3\xed",     3); break;
  case SP:   append_bytes(s, "\x66\xd3\xec",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xd3\xe8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xd3\xe9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xd3\xea", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xd3\xeb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xd3\xec", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xd3\xed", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xd3\xee", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xd3\xef", 4); break;
  }
}

ELF_DEF void gen_shl_16_r_1(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xd1\xe0",     3); break;
  case BX:   append_bytes(s, "\x66\xd1\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\xd1\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\xd1\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\xd1\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\xd1\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\xd1\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\xd1\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xd1\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xd1\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xd1\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xd1\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xd1\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xd1\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xd1\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xd1\xe7", 4); break;
  }
}

ELF_DEF void gen_shl_16_r_imm(Bytes *s, Register r, char shl) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xc1\xe0",     3); break;
  case BX:   append_bytes(s, "\x66\xc1\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\xc1\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\xc1\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\xc1\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\xc1\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\xc1\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\xc1\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xc1\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xc1\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xc1\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xc1\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xc1\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xc1\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xc1\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xc1\xe7", 4); break;
  }

  da_append(s, shl);
}

ELF_DEF void gen_shl_16_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xd3\xe0",     3); break;
  case BX:   append_bytes(s, "\x66\xd3\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\xd3\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\xd3\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\xd3\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\xd3\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\xd3\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\xd3\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xd3\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xd3\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xd3\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xd3\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xd3\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xd3\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xd3\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xd3\xe7", 4); break;
  }
}

ELF_DEF void gen_sar_16_r_1(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s,"\x66\xd1\xf8",     3); break;
  case BX:   append_bytes(s,"\x66\xd1\xfb",     3); break;
  case CX:   append_bytes(s,"\x66\xd1\xf9",     3); break;
  case DX:   append_bytes(s,"\x66\xd1\xfa",     3); break;
  case SI:   append_bytes(s,"\x66\xd1\xfe",     3); break;
  case DI:   append_bytes(s,"\x66\xd1\xff",     3); break;
  case BP:   append_bytes(s,"\x66\xd1\xfd",     3); break;
  case SP:   append_bytes(s,"\x66\xd1\xfc",     3); break;
  case R8W:  append_bytes(s,"\x66\x41\xd1\xf8", 4); break;
  case R9W:  append_bytes(s,"\x66\x41\xd1\xf9", 4); break;
  case R10W: append_bytes(s,"\x66\x41\xd1\xfa", 4); break;
  case R11W: append_bytes(s,"\x66\x41\xd1\xfb", 4); break;
  case R12W: append_bytes(s,"\x66\x41\xd1\xfc", 4); break;
  case R13W: append_bytes(s,"\x66\x41\xd1\xfd", 4); break;
  case R14W: append_bytes(s,"\x66\x41\xd1\xfe", 4); break;
  case R15W: append_bytes(s,"\x66\x41\xd1\xff", 4); break;
  }
}

ELF_DEF void gen_sar_16_r_imm(Bytes *s, Register r, char sar) {
  switch (r) {
  case AX:   append_bytes(s,"\x66\xc1\xf8\x0a",     4); break;
  case BX:   append_bytes(s,"\x66\xc1\xfb\x0a",     4); break;
  case CX:   append_bytes(s,"\x66\xc1\xf9\x0a",     4); break;
  case DX:   append_bytes(s,"\x66\xc1\xfa\x0a",     4); break;
  case SI:   append_bytes(s,"\x66\xc1\xfe\x0a",     4); break;
  case DI:   append_bytes(s,"\x66\xc1\xff\x0a",     4); break;
  case BP:   append_bytes(s,"\x66\xc1\xfd\x0a",     4); break;
  case SP:   append_bytes(s,"\x66\xc1\xfc\x0a",     4); break;
  case R8W:  append_bytes(s,"\x66\x41\xc1\xf8\x0a", 5); break;
  case R9W:  append_bytes(s,"\x66\x41\xc1\xf9\x0a", 5); break;
  case R10W: append_bytes(s,"\x66\x41\xc1\xfa\x0a", 5); break;
  case R11W: append_bytes(s,"\x66\x41\xc1\xfb\x0a", 5); break;
  case R12W: append_bytes(s,"\x66\x41\xc1\xfc\x0a", 5); break;
  case R13W: append_bytes(s,"\x66\x41\xc1\xfd\x0a", 5); break;
  case R14W: append_bytes(s,"\x66\x41\xc1\xfe\x0a", 5); break;
  case R15W: append_bytes(s,"\x66\x41\xc1\xff\x0a", 5); break;
  }

  da_append(s, sar);
}

ELF_DEF void gen_sar_16_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AX:  append_bytes(s, "\x66\xd3\xf8",      3); break;
  case BX:  append_bytes(s, "\x66\xd3\xfb",      3); break;
  case CX:  append_bytes(s, "\x66\xd3\xf9",      3); break;
  case DX:  append_bytes(s, "\x66\xd3\xfa",      3); break;
  case SI:  append_bytes(s, "\x66\xd3\xfe",      3); break;
  case DI:  append_bytes(s, "\x66\xd3\xff",      3); break;
  case BP:  append_bytes(s, "\x66\xd3\xfd",      3); break;
  case SP:  append_bytes(s, "\x66\xd3\xfc",      3); break;
  case R8W:  append_bytes(s, "\x66\x41\xd3\xf8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xd3\xf9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xd3\xfa", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xd3\xfb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xd3\xfc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xd3\xfd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xd3\xfe", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xd3\xff", 4); break;
  }
}

ELF_DEF void gen_cmp_16_r_imm_short_form(Bytes *s, Register r, char cmp) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x83\xf8",     3); break;
  case BX:   append_bytes(s, "\x66\x83\xfb",     3); break;
  case CX:   append_bytes(s, "\x66\x83\xf9",     3); break;
  case DX:   append_bytes(s, "\x66\x83\xfa",     3); break;
  case SI:   append_bytes(s, "\x66\x83\xfe",     3); break;
  case DI:   append_bytes(s, "\x66\x83\xff",     3); break;
  case BP:   append_bytes(s, "\x66\x83\xfd",     3); break;
  case SP:   append_bytes(s, "\x66\x83\xfc",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x83\xf8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x83\xf9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x83\xfa", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x83\xfb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x83\xfc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x83\xfd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x83\xfe", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x83\xff", 4); break;
  }

  da_append(s, cmp);
}

ELF_DEF void gen_cmp_16_r_imm_long_form(Bytes *s, Register r, size_t cmp) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x3d",         2); break;
  case BX:   append_bytes(s, "\x66\x81\xfb",     3); break;
  case CX:   append_bytes(s, "\x66\x81\xf9",     3); break;
  case DX:   append_bytes(s, "\x66\x81\xfa",     3); break;
  case SI:   append_bytes(s, "\x66\x81\xfe",     3); break;
  case DI:   append_bytes(s, "\x66\x81\xff",     3); break;
  case BP:   append_bytes(s, "\x66\x81\xfd",     3); break;
  case SP:   append_bytes(s, "\x66\x81\xfc",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\x81\xf8", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\x81\xf9", 4); break;
  case R10W: append_bytes(s, "\x66\x41\x81\xfa", 4); break;
  case R11W: append_bytes(s, "\x66\x41\x81\xfb", 4); break;
  case R12W: append_bytes(s, "\x66\x41\x81\xfc", 4); break;
  case R13W: append_bytes(s, "\x66\x41\x81\xfd", 4); break;
  case R14W: append_bytes(s, "\x66\x41\x81\xfe", 4); break;
  case R15W: append_bytes(s, "\x66\x41\x81\xff", 4); break;
  }

  gen_little_endian(s, cmp, 2);
}

ELF_DEF void gen_push_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x50",     2); break;
  case BX:   append_bytes(s, "\x66\x53",     2); break;
  case CX:   append_bytes(s, "\x66\x51",     2); break;
  case DX:   append_bytes(s, "\x66\x52",     2); break;
  case SI:   append_bytes(s, "\x66\x56",     2); break;
  case DI:   append_bytes(s, "\x66\x57",     2); break;
  case BP:   append_bytes(s, "\x66\x55",     2); break;
  case SP:   append_bytes(s, "\x66\x54",     2); break;
  case R8W:  append_bytes(s, "\x66\x41\x50", 3); break;
  case R9W:  append_bytes(s, "\x66\x41\x51", 3); break;
  case R10W: append_bytes(s, "\x66\x41\x52", 3); break;
  case R11W: append_bytes(s, "\x66\x41\x53", 3); break;
  case R12W: append_bytes(s, "\x66\x41\x54", 3); break;
  case R13W: append_bytes(s, "\x66\x41\x55", 3); break;
  case R14W: append_bytes(s, "\x66\x41\x56", 3); break;
  case R15W: append_bytes(s, "\x66\x41\x57", 3); break;
  }
}

ELF_DEF void gen_pop_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\x58",     2); break;
  case BX:   append_bytes(s, "\x66\x5b",     2); break;
  case CX:   append_bytes(s, "\x66\x59",     2); break;
  case DX:   append_bytes(s, "\x66\x5a",     2); break;
  case SI:   append_bytes(s, "\x66\x5e",     2); break;
  case DI:   append_bytes(s, "\x66\x5f",     2); break;
  case BP:   append_bytes(s, "\x66\x5d",     2); break;
  case SP:   append_bytes(s, "\x66\x5c",     2); break;
  case R8W:  append_bytes(s, "\x66\x41\x58", 3); break;
  case R9W:  append_bytes(s, "\x66\x41\x59", 3); break;
  case R10W: append_bytes(s, "\x66\x41\x5a", 3); break;
  case R11W: append_bytes(s, "\x66\x41\x5b", 3); break;
  case R12W: append_bytes(s, "\x66\x41\x5c", 3); break;
  case R13W: append_bytes(s, "\x66\x41\x5d", 3); break;
  case R14W: append_bytes(s, "\x66\x41\x5e", 3); break;
  case R15W: append_bytes(s, "\x66\x41\x5f", 3); break;
  }
}

ELF_DEF void gen_jmp_r_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xff\xe0",     3); break;
  case BX:   append_bytes(s, "\x66\xff\xe3",     3); break;
  case CX:   append_bytes(s, "\x66\xff\xe1",     3); break;
  case DX:   append_bytes(s, "\x66\xff\xe2",     3); break;
  case SI:   append_bytes(s, "\x66\xff\xe6",     3); break;
  case DI:   append_bytes(s, "\x66\xff\xe7",     3); break;
  case BP:   append_bytes(s, "\x66\xff\xe5",     3); break;
  case SP:   append_bytes(s, "\x66\xff\xe4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xff\xe0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xff\xe1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xff\xe2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xff\xe3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xff\xe4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xff\xe5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xff\xe6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xff\xe7", 4); break;
  }
}

ELF_DEF void gen_call_r_16(Bytes *s, Register r) {
  switch (r) {
  case AX:   append_bytes(s, "\x66\xff\xd0",     3); break;
  case BX:   append_bytes(s, "\x66\xff\xd3",     3); break;
  case CX:   append_bytes(s, "\x66\xff\xd1",     3); break;
  case DX:   append_bytes(s, "\x66\xff\xd2",     3); break;
  case SI:   append_bytes(s, "\x66\xff\xd6",     3); break;
  case DI:   append_bytes(s, "\x66\xff\xd7",     3); break;
  case BP:   append_bytes(s, "\x66\xff\xd5",     3); break;
  case SP:   append_bytes(s, "\x66\xff\xd4",     3); break;
  case R8W:  append_bytes(s, "\x66\x41\xff\xd0", 4); break;
  case R9W:  append_bytes(s, "\x66\x41\xff\xd1", 4); break;
  case R10W: append_bytes(s, "\x66\x41\xff\xd2", 4); break;
  case R11W: append_bytes(s, "\x66\x41\xff\xd3", 4); break;
  case R12W: append_bytes(s, "\x66\x41\xff\xd4", 4); break;
  case R13W: append_bytes(s, "\x66\x41\xff\xd5", 4); break;
  case R14W: append_bytes(s, "\x66\x41\xff\xd6", 4); break;
  case R15W: append_bytes(s, "\x66\x41\xff\xd7", 4); break;
  }
}

// ************************* 8-bits *************************
ELF_DEF void gen_add_r_imm_8(Bytes *s, Register r, char add) {
  switch (r) {
  case AL:   da_append(s,    0x04);              break;
  case AH:   append_bytes(s, "\x80\xc4",     2); break;
  case BL:   append_bytes(s, "\x80\xc3",     2); break;
  case BH:   append_bytes(s, "\x80\xc7",     2); break;
  case CL:   append_bytes(s, "\x80\xc1",     2); break;
  case CH:   append_bytes(s, "\x80\xc5",     2); break;
  case DL:   append_bytes(s, "\x80\xc2",     2); break;
  case DH:   append_bytes(s, "\x80\xc6",     2); break;
  case SIL:  append_bytes(s, "\x40\x80\xc6", 3); break;
  case DIL:  append_bytes(s, "\x40\x80\xc7", 3); break;
  case BPL:  append_bytes(s, "\x40\x80\xc5", 3); break;
  case SPL:  append_bytes(s, "\x40\x80\xc4", 3); break;
  case R8B:  append_bytes(s, "\x41\x80\xc0", 3); break;
  case R9B:  append_bytes(s, "\x41\x80\xc1", 3); break;
  case R10B: append_bytes(s, "\x41\x80\xc2", 3); break;
  case R11B: append_bytes(s, "\x41\x80\xc3", 3); break;
  case R12B: append_bytes(s, "\x41\x80\xc4", 3); break;
  case R13B: append_bytes(s, "\x41\x80\xc5", 3); break;
  case R14B: append_bytes(s, "\x41\x80\xc6", 3); break;
  case R15B: append_bytes(s, "\x41\x80\xc7", 3); break;
  }

  da_append(s, add);
}

ELF_DEF void gen_sub_r_imm_8(Bytes *s, Register r, char sub) {
  switch (r) {
  case AL:   da_append(s,    0x2c);              break;
  case AH:   append_bytes(s, "\x80\xec",     2); break;
  case BL:   append_bytes(s, "\x80\xeb",     2); break;
  case BH:   append_bytes(s, "\x80\xef",     2); break;
  case CL:   append_bytes(s, "\x80\xe9",     2); break;
  case CH:   append_bytes(s, "\x80\xed",     2); break;
  case DL:   append_bytes(s, "\x80\xea",     2); break;
  case DH:   append_bytes(s, "\x80\xee",     2); break;
  case SIL:  append_bytes(s, "\x40\x80\xee", 3); break;
  case DIL:  append_bytes(s, "\x40\x80\xef", 3); break;
  case BPL:  append_bytes(s, "\x40\x80\xed", 3); break;
  case SPL:  append_bytes(s, "\x40\x80\xec", 3); break;
  case R8B:  append_bytes(s, "\x41\x80\xe8", 3); break;
  case R9B:  append_bytes(s, "\x41\x80\xe9", 3); break;
  case R10B: append_bytes(s, "\x41\x80\xea", 3); break;
  case R11B: append_bytes(s, "\x41\x80\xeb", 3); break;
  case R12B: append_bytes(s, "\x41\x80\xec", 3); break;
  case R13B: append_bytes(s, "\x41\x80\xed", 3); break;
  case R14B: append_bytes(s, "\x41\x80\xee", 3); break;
  case R15B: append_bytes(s, "\x41\x80\xef", 3); break;
  }

  da_append(s, sub);
}

ELF_DEF void gen_inc_8(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xfe\xc0",     2); break;
  case AH:   append_bytes(s, "\xfe\xc4",     2); break;
  case BL:   append_bytes(s, "\xfe\xc3",     2); break;
  case BH:   append_bytes(s, "\xfe\xc7",     2); break;
  case CL:   append_bytes(s, "\xfe\xc1",     2); break;
  case CH:   append_bytes(s, "\xfe\xc5",     2); break;
  case DL:   append_bytes(s, "\xfe\xc2",     2); break;
  case DH:   append_bytes(s, "\xfe\xc6",     2); break;
  case SIL:  append_bytes(s, "\x40\xfe\xc6", 3); break;
  case DIL:  append_bytes(s, "\x40\xfe\xc7", 3); break;
  case BPL:  append_bytes(s, "\x40\xfe\xc5", 3); break;
  case SPL:  append_bytes(s, "\x40\xfe\xc4", 3); break;
  case R8B:  append_bytes(s, "\x41\xfe\xc0", 3); break;
  case R9B:  append_bytes(s, "\x41\xfe\xc1", 3); break;
  case R10B: append_bytes(s, "\x41\xfe\xc2", 3); break;
  case R11B: append_bytes(s, "\x41\xfe\xc3", 3); break;
  case R12B: append_bytes(s, "\x41\xfe\xc4", 3); break;
  case R13B: append_bytes(s, "\x41\xfe\xc5", 3); break;
  case R14B: append_bytes(s, "\x41\xfe\xc6", 3); break;
  case R15B: append_bytes(s, "\x41\xfe\xc7", 3); break;
  }
}

ELF_DEF void gen_dec_8(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xfe\xc8",     2); break;
  case AH:   append_bytes(s, "\xfe\xcc",     2); break;
  case BL:   append_bytes(s, "\xfe\xcb",     2); break;
  case BH:   append_bytes(s, "\xfe\xcf",     2); break;
  case CL:   append_bytes(s, "\xfe\xc9",     2); break;
  case CH:   append_bytes(s, "\xfe\xcd",     2); break;
  case DL:   append_bytes(s, "\xfe\xca",     2); break;
  case DH:   append_bytes(s, "\xfe\xce",     2); break;
  case SIL:  append_bytes(s, "\x40\xfe\xce", 3); break;
  case DIL:  append_bytes(s, "\x40\xfe\xcf", 3); break;
  case BPL:  append_bytes(s, "\x40\xfe\xcd", 3); break;
  case SPL:  append_bytes(s, "\x40\xfe\xcc", 3); break;
  case R8B:  append_bytes(s, "\x41\xfe\xc8", 3); break;
  case R9B:  append_bytes(s, "\x41\xfe\xc9", 3); break;
  case R10B: append_bytes(s, "\x41\xfe\xca", 3); break;
  case R11B: append_bytes(s, "\x41\xfe\xcb", 3); break;
  case R12B: append_bytes(s, "\x41\xfe\xcc", 3); break;
  case R13B: append_bytes(s, "\x41\xfe\xcd", 3); break;
  case R14B: append_bytes(s, "\x41\xfe\xce", 3); break;
  case R15B: append_bytes(s, "\x41\xfe\xcf", 3); break;
  }  
}

ELF_DEF void gen_div_8(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xf6\xf0",     2); break;
  case AH:   append_bytes(s, "\xf6\xf4",     2); break;
  case BL:   append_bytes(s, "\xf6\xf3",     2); break;
  case BH:   append_bytes(s, "\xf6\xf7",     2); break;
  case CL:   append_bytes(s, "\xf6\xf1",     2); break;
  case CH:   append_bytes(s, "\xf6\xf5",     2); break;
  case DL:   append_bytes(s, "\xf6\xf2",     2); break;
  case DH:   append_bytes(s, "\xf6\xf6",     2); break;
  case SIL:  append_bytes(s, "\x40\xf6\xf6", 3); break;
  case DIL:  append_bytes(s, "\x40\xf6\xf7", 3); break;
  case BPL:  append_bytes(s, "\x40\xf6\xf5", 3); break;
  case SPL:  append_bytes(s, "\x40\xf6\xf4", 3); break;
  case R8B:  append_bytes(s, "\x41\xf6\xf0", 3); break;
  case R9B:  append_bytes(s, "\x41\xf6\xf1", 3); break;
  case R10B: append_bytes(s, "\x41\xf6\xf2", 3); break;
  case R11B: append_bytes(s, "\x41\xf6\xf3", 3); break;
  case R12B: append_bytes(s, "\x41\xf6\xf4", 3); break;
  case R13B: append_bytes(s, "\x41\xf6\xf5", 3); break;
  case R14B: append_bytes(s, "\x41\xf6\xf6", 3); break;
  case R15B: append_bytes(s, "\x41\xf6\xf7", 3); break;
  }
}

ELF_DEF void gen_and_r_imm_8(Bytes *s, Register r, char and) {
  switch (r) {
  case AL:   da_append(s,    0x24);              break;
  case AH:   append_bytes(s, "\x80\xe4",     2); break;
  case BL:   append_bytes(s, "\x80\xe3",     2); break;
  case BH:   append_bytes(s, "\x80\xe7",     2); break;
  case CL:   append_bytes(s, "\x80\xe1",     2); break;
  case CH:   append_bytes(s, "\x80\xe5",     2); break;
  case DL:   append_bytes(s, "\x80\xe2",     2); break;
  case DH:   append_bytes(s, "\x80\xe6",     2); break;
  case SIL:  append_bytes(s, "\x40\x80\xe6", 3); break;
  case DIL:  append_bytes(s, "\x40\x80\xe7", 3); break;
  case BPL:  append_bytes(s, "\x40\x80\xe5", 3); break;
  case SPL:  append_bytes(s, "\x40\x80\xe4", 3); break;
  case R8B:  append_bytes(s, "\x41\x80\xe0", 3); break;
  case R9B:  append_bytes(s, "\x41\x80\xe1", 3); break;
  case R10B: append_bytes(s, "\x41\x80\xe2", 3); break;
  case R11B: append_bytes(s, "\x41\x80\xe3", 3); break;
  case R12B: append_bytes(s, "\x41\x80\xe4", 3); break;
  case R13B: append_bytes(s, "\x41\x80\xe5", 3); break;
  case R14B: append_bytes(s, "\x41\x80\xe6", 3); break;
  case R15B: append_bytes(s, "\x41\x80\xe7", 3); break;
  }

  da_append(s, and);
}

ELF_DEF void gen_or_r_imm_8(Bytes *s, Register r, char or) {
  switch (r) {
  case AL:   da_append(s,    0x0c);              break;
  case AH:   append_bytes(s, "\x80\xcc",     2); break;
  case BL:   append_bytes(s, "\x80\xcb",     2); break;
  case BH:   append_bytes(s, "\x80\xcf",     2); break;
  case CL:   append_bytes(s, "\x80\xc9",     2); break;
  case CH:   append_bytes(s, "\x80\xcd",     2); break;
  case DL:   append_bytes(s, "\x80\xca",     2); break;
  case DH:   append_bytes(s, "\x80\xce",     2); break;
  case SIL:  append_bytes(s, "\x40\x80\xce", 3); break;
  case DIL:  append_bytes(s, "\x40\x80\xcf", 3); break;
  case BPL:  append_bytes(s, "\x40\x80\xcd", 3); break;
  case SPL:  append_bytes(s, "\x40\x80\xcc", 3); break;
  case R8B:  append_bytes(s, "\x41\x80\xc8", 3); break;
  case R9B:  append_bytes(s, "\x41\x80\xc9", 3); break;
  case R10B: append_bytes(s, "\x41\x80\xca", 3); break;
  case R11B: append_bytes(s, "\x41\x80\xcb", 3); break;
  case R12B: append_bytes(s, "\x41\x80\xcc", 3); break;
  case R13B: append_bytes(s, "\x41\x80\xcd", 3); break;
  case R14B: append_bytes(s, "\x41\x80\xce", 3); break;
  case R15B: append_bytes(s, "\x41\x80\xcf", 3); break;
  }

  da_append(s, or);
}

ELF_DEF void gen_not_8(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xf6\xd0",     2); break;
  case AH:   append_bytes(s, "\xf6\xd4",     2); break;
  case BL:   append_bytes(s, "\xf6\xd3",     2); break;
  case BH:   append_bytes(s, "\xf6\xd7",     2); break;
  case CL:   append_bytes(s, "\xf6\xd1",     2); break;
  case CH:   append_bytes(s, "\xf6\xd5",     2); break;
  case DL:   append_bytes(s, "\xf6\xd2",     2); break;
  case DH:   append_bytes(s, "\xf6\xd6",     2); break;
  case SIL:  append_bytes(s, "\x40\xf6\xd6", 3); break;
  case DIL:  append_bytes(s, "\x40\xf6\xd7", 3); break;
  case BPL:  append_bytes(s, "\x40\xf6\xd5", 3); break;
  case SPL:  append_bytes(s, "\x40\xf6\xd4", 3); break;
  case R8B:  append_bytes(s, "\x41\xf6\xd0", 3); break;
  case R9B:  append_bytes(s, "\x41\xf6\xd1", 3); break;
  case R10B: append_bytes(s, "\x41\xf6\xd2", 3); break;
  case R11B: append_bytes(s, "\x41\xf6\xd3", 3); break;
  case R12B: append_bytes(s, "\x41\xf6\xd4", 3); break;
  case R13B: append_bytes(s, "\x41\xf6\xd5", 3); break;
  case R14B: append_bytes(s, "\x41\xf6\xd6", 3); break;
  case R15B: append_bytes(s, "\x41\xf6\xd7", 3); break;
  }
}

ELF_DEF void gen_shr_8_r_1(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xd0\xe8",    2); break;
  case AH:   append_bytes(s, "\xd0\xec",    2); break;
  case BL:   append_bytes(s, "\xd0\xeb",    2); break;
  case BH:   append_bytes(s, "\xd0\xef",    2); break;
  case CL:   append_bytes(s, "\xd0\xe9",    2); break;
  case CH:   append_bytes(s, "\xd0\xed",    2); break;
  case DL:   append_bytes(s, "\xd0\xea",    2); break;
  case DH:   append_bytes(s, "\xd0\xee",    2); break;
  case SIL:  append_bytes(s, "\x40\xd\xee", 3); break;
  case DIL:  append_bytes(s, "\x40\xd\xef", 3); break;
  case BPL:  append_bytes(s, "\x40\xd\xed", 3); break;
  case SPL:  append_bytes(s, "\x40\xd\xec", 3); break;
  case R8B:  append_bytes(s, "\x41\xd\xe8", 3); break;
  case R9B:  append_bytes(s, "\x41\xd\xe9", 3); break;
  case R10B: append_bytes(s, "\x41\xd\xea", 3); break;
  case R11B: append_bytes(s, "\x41\xd\xeb", 3); break;
  case R12B: append_bytes(s, "\x41\xd\xec", 3); break;
  case R13B: append_bytes(s, "\x41\xd\xed", 3); break;
  case R14B: append_bytes(s, "\x41\xd\xee", 3); break;
  case R15B: append_bytes(s, "\x41\xd\xef", 3); break;
  }
}

ELF_DEF void gen_shr_8_r_imm(Bytes *s, Register r, char shr) {
  switch (r) {
  case AL:   append_bytes(s, "\xc0\xe8",     3); break;
  case AH:   append_bytes(s, "\xc0\xec",     3); break;
  case BL:   append_bytes(s, "\xc0\xeb",     3); break;
  case BH:   append_bytes(s, "\xc0\xef",     3); break;
  case CL:   append_bytes(s, "\xc0\xe9",     3); break;
  case CH:   append_bytes(s, "\xc0\xed",     3); break;
  case DL:   append_bytes(s, "\xc0\xea",     3); break;
  case DH:   append_bytes(s, "\xc0\xee",     3); break;
  case SIL:  append_bytes(s, "\x40\xc0\xee", 3); break;
  case DIL:  append_bytes(s, "\x40\xc0\xef", 3); break;
  case BPL:  append_bytes(s, "\x40\xc0\xed", 3); break;
  case SPL:  append_bytes(s, "\x40\xc0\xec", 3); break;
  case R8B:  append_bytes(s, "\x41\xc0\xe8", 3); break;
  case R9B:  append_bytes(s, "\x41\xc0\xe9", 3); break;
  case R10B: append_bytes(s, "\x41\xc0\xea", 3); break;
  case R11B: append_bytes(s, "\x41\xc0\xeb", 3); break;
  case R12B: append_bytes(s, "\x41\xc0\xec", 3); break;
  case R13B: append_bytes(s, "\x41\xc0\xed", 3); break;
  case R14B: append_bytes(s, "\x41\xc0\xee", 3); break;
  case R15B: append_bytes(s, "\x41\xc0\xef", 3); break;
  }

  da_append(s, shr);
}

ELF_DEF void gen_shr_8_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xd2\xe8",     2); break;
  case AH:   append_bytes(s, "\xd2\xec",     2); break;
  case BL:   append_bytes(s, "\xd2\xeb",     2); break;
  case BH:   append_bytes(s, "\xd2\xef",     2); break;
  case CL:   append_bytes(s, "\xd2\xe9",     2); break;
  case CH:   append_bytes(s, "\xd2\xed",     2); break;
  case DL:   append_bytes(s, "\xd2\xea",     2); break;
  case DH:   append_bytes(s, "\xd2\xee",     2); break;
  case SIL:  append_bytes(s, "\x40\xd2\xee", 3); break;
  case DIL:  append_bytes(s, "\x40\xd2\xef", 3); break;
  case BPL:  append_bytes(s, "\x40\xd2\xed", 3); break;
  case SPL:  append_bytes(s, "\x40\xd2\xec", 3); break;
  case R8B:  append_bytes(s, "\x41\xd2\xe8", 3); break;
  case R9B:  append_bytes(s, "\x41\xd2\xe9", 3); break;
  case R10B: append_bytes(s, "\x41\xd2\xea", 3); break;
  case R11B: append_bytes(s, "\x41\xd2\xeb", 3); break;
  case R12B: append_bytes(s, "\x41\xd2\xec", 3); break;
  case R13B: append_bytes(s, "\x41\xd2\xed", 3); break;
  case R14B: append_bytes(s, "\x41\xd2\xee", 3); break;
  case R15B: append_bytes(s, "\x41\xd2\xef", 3); break;
  }
}

ELF_DEF void gen_shl_8_r_1(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xd0\xe0",     2); break;
  case AH:   append_bytes(s, "\xd0\xe4",     2); break;
  case BL:   append_bytes(s, "\xd0\xe3",     2); break;
  case BH:   append_bytes(s, "\xd0\xe7",     2); break;
  case CL:   append_bytes(s, "\xd0\xe1",     2); break;
  case CH:   append_bytes(s, "\xd0\xe5",     2); break;
  case DL:   append_bytes(s, "\xd0\xe2",     2); break;
  case DH:   append_bytes(s, "\xd0\xe6",     2); break;
  case SIL:  append_bytes(s, "\x40\xd0\xe6", 3); break;
  case DIL:  append_bytes(s, "\x40\xd0\xe7", 3); break;
  case BPL:  append_bytes(s, "\x40\xd0\xe5", 3); break;
  case SPL:  append_bytes(s, "\x40\xd0\xe4", 3); break;
  case R8B:  append_bytes(s, "\x41\xd0\xe0", 3); break;
  case R9B:  append_bytes(s, "\x41\xd0\xe1", 3); break;
  case R10B: append_bytes(s, "\x41\xd0\xe2", 3); break;
  case R11B: append_bytes(s, "\x41\xd0\xe3", 3); break;
  case R12B: append_bytes(s, "\x41\xd0\xe4", 3); break;
  case R13B: append_bytes(s, "\x41\xd0\xe5", 3); break;
  case R14B: append_bytes(s, "\x41\xd0\xe6", 3); break;
  case R15B: append_bytes(s, "\x41\xd0\xe7", 3); break;
  }
}

ELF_DEF void gen_shl_8_r_imm(Bytes *s, Register r, char shl) {
  switch (r) {
  case AL:   append_bytes(s, "\xc0\xe0",     2); break;
  case AH:   append_bytes(s, "\xc0\xe4",     2); break;
  case BL:   append_bytes(s, "\xc0\xe3",     2); break;
  case BH:   append_bytes(s, "\xc0\xe7",     2); break;
  case CL:   append_bytes(s, "\xc0\xe1",     2); break;
  case CH:   append_bytes(s, "\xc0\xe5",     2); break;
  case DL:   append_bytes(s, "\xc0\xe2",     2); break;
  case DH:   append_bytes(s, "\xc0\xe6",     2); break;
  case SIL:  append_bytes(s, "\x40\xc0\xe6", 3); break;
  case DIL:  append_bytes(s, "\x40\xc0\xe7", 3); break;
  case BPL:  append_bytes(s, "\x40\xc0\xe5", 3); break;
  case SPL:  append_bytes(s, "\x40\xc0\xe4", 3); break;
  case R8B:  append_bytes(s, "\x41\xc0\xe0", 3); break;
  case R9B:  append_bytes(s, "\x41\xc0\xe1", 3); break;
  case R10B: append_bytes(s, "\x41\xc0\xe2", 3); break;
  case R11B: append_bytes(s, "\x41\xc0\xe3", 3); break;
  case R12B: append_bytes(s, "\x41\xc0\xe4", 3); break;
  case R13B: append_bytes(s, "\x41\xc0\xe5", 3); break;
  case R14B: append_bytes(s, "\x41\xc0\xe6", 3); break;
  case R15B: append_bytes(s, "\x41\xc0\xe7", 3); break;
  }

  da_append(s, shl);
}

ELF_DEF void gen_shl_8_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xd2\xe0",     2); break;
  case AH:   append_bytes(s, "\xd2\xe4",     2); break;
  case BL:   append_bytes(s, "\xd2\xe3",     2); break;
  case BH:   append_bytes(s, "\xd2\xe7",     2); break;
  case CL:   append_bytes(s, "\xd2\xe1",     2); break;
  case CH:   append_bytes(s, "\xd2\xe5",     2); break;
  case DL:   append_bytes(s, "\xd2\xe2",     2); break;
  case DH:   append_bytes(s, "\xd2\xe6",     2); break;
  case SIL:  append_bytes(s, "\x40\xd2\xe6", 3); break;
  case DIL:  append_bytes(s, "\x40\xd2\xe7", 3); break;
  case BPL:  append_bytes(s, "\x40\xd2\xe5", 3); break;
  case SPL:  append_bytes(s, "\x40\xd2\xe4", 3); break;
  case R8B:  append_bytes(s, "\x41\xd2\xe0", 3); break;
  case R9B:  append_bytes(s, "\x41\xd2\xe1", 3); break;
  case R10B: append_bytes(s, "\x41\xd2\xe2", 3); break;
  case R11B: append_bytes(s, "\x41\xd2\xe3", 3); break;
  case R12B: append_bytes(s, "\x41\xd2\xe4", 3); break;
  case R13B: append_bytes(s, "\x41\xd2\xe5", 3); break;
  case R14B: append_bytes(s, "\x41\xd2\xe6", 3); break;
  case R15B: append_bytes(s, "\x41\xd2\xe7", 3); break;
  }
}

ELF_DEF void gen_sar_8_r_1(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s,"\xd0\xf8",     2); break;
  case AH:   append_bytes(s,"\xd0\xfc",     2); break;
  case BL:   append_bytes(s,"\xd0\xfb",     2); break;
  case BH:   append_bytes(s,"\xd0\xff",     2); break;
  case CL:   append_bytes(s,"\xd0\xf9",     2); break;
  case CH:   append_bytes(s,"\xd0\xfd",     2); break;
  case DL:   append_bytes(s,"\xd0\xfa",     2); break;
  case DH:   append_bytes(s,"\xd0\xfe",     2); break;
  case SIL:  append_bytes(s,"\x40\xd0\xfe", 3); break;
  case DIL:  append_bytes(s,"\x40\xd0\xff", 3); break;
  case BPL:  append_bytes(s,"\x40\xd0\xfd", 3); break;
  case SPL:  append_bytes(s,"\x40\xd0\xfc", 3); break;
  case R8B:  append_bytes(s,"\x41\xd0\xf8", 3); break;
  case R9B:  append_bytes(s,"\x41\xd0\xf9", 3); break;
  case R10B: append_bytes(s,"\x41\xd0\xfa", 3); break;
  case R11B: append_bytes(s,"\x41\xd0\xfb", 3); break;
  case R12B: append_bytes(s,"\x41\xd0\xfc", 3); break;
  case R13B: append_bytes(s,"\x41\xd0\xfd", 3); break;
  case R14B: append_bytes(s,"\x41\xd0\xfe", 3); break;
  case R15B: append_bytes(s,"\x41\xd0\xff", 3); break;
  }
}

ELF_DEF void gen_sar_8_r_imm(Bytes *s, Register r, char sar) {
  switch (r) {
  case AL:   append_bytes(s, "\xc0\xf8\x0a",     3); break;
  case AH:   append_bytes(s, "\xc0\xfc\x0a",     3); break;
  case BL:   append_bytes(s, "\xc0\xfb\x0a",     3); break;
  case BH:   append_bytes(s, "\xc0\xff\x0a",     3); break;
  case CL:   append_bytes(s, "\xc0\xf9\x0a",     3); break;
  case CH:   append_bytes(s, "\xc0\xfd\x0a",     3); break;
  case DL:   append_bytes(s, "\xc0\xfa\x0a",     3); break;
  case DH:   append_bytes(s, "\xc0\xfe\x0a",     3); break;
  case SIL:  append_bytes(s, "\x40\xc0\xfe\x0a", 4); break;
  case DIL:  append_bytes(s, "\x40\xc0\xff\x0a", 4); break;
  case BPL:  append_bytes(s, "\x40\xc0\xfd\x0a", 4); break;
  case SPL:  append_bytes(s, "\x40\xc0\xfc\x0a", 4); break;
  case R8B:  append_bytes(s, "\x41\xc0\xf8\x0a", 4); break;
  case R9B:  append_bytes(s, "\x41\xc0\xf9\x0a", 4); break;
  case R10B: append_bytes(s, "\x41\xc0\xfa\x0a", 4); break;
  case R11B: append_bytes(s, "\x41\xc0\xfb\x0a", 4); break;
  case R12B: append_bytes(s, "\x41\xc0\xfc\x0a", 4); break;
  case R13B: append_bytes(s, "\x41\xc0\xfd\x0a", 4); break;
  case R14B: append_bytes(s, "\x41\xc0\xfe\x0a", 4); break;
  case R15B: append_bytes(s, "\x41\xc0\xff\x0a", 4); break;
  }
}

ELF_DEF void gen_sar_8_r_cl(Bytes *s, Register r) {
  switch (r) {
  case AL:   append_bytes(s, "\xd2\xf8",     2); break;
  case AH:   append_bytes(s, "\xd2\xfc",     2); break;
  case BL:   append_bytes(s, "\xd2\xfb",     2); break;
  case BH:   append_bytes(s, "\xd2\xff",     2); break;
  case CL:   append_bytes(s, "\xd2\xf9",     2); break;
  case CH:   append_bytes(s, "\xd2\xfd",     2); break;
  case DL:   append_bytes(s, "\xd2\xfa",     2); break;
  case DH:   append_bytes(s, "\xd2\xfe",     2); break;
  case SIL:  append_bytes(s, "\x40\xd2\xfe", 3); break;
  case DIL:  append_bytes(s, "\x40\xd2\xff", 3); break;
  case BPL:  append_bytes(s, "\x40\xd2\xfd", 3); break;
  case SPL:  append_bytes(s, "\x40\xd2\xfc", 3); break;
  case R8B:  append_bytes(s, "\x41\xd2\xf8", 3); break;
  case R9B:  append_bytes(s, "\x41\xd2\xf9", 3); break;
  case R10B: append_bytes(s, "\x41\xd2\xfa", 3); break;
  case R11B: append_bytes(s, "\x41\xd2\xfb", 3); break;
  case R12B: append_bytes(s, "\x41\xd2\xfc", 3); break;
  case R13B: append_bytes(s, "\x41\xd2\xfd", 3); break;
  case R14B: append_bytes(s, "\x41\xd2\xfe", 3); break;
  case R15B: append_bytes(s, "\x41\xd2\xff", 3); break;
  }
}

ELF_DEF void gen_cmp_r_imm_8(Bytes *s, Register r, char cmp) {
  switch (r) {
  case AL:   da_append(s,    0x3c);              break;
  case AH:   append_bytes(s, "\x80\xfc",     2); break;
  case BL:   append_bytes(s, "\x80\xfb",     2); break;
  case BH:   append_bytes(s, "\x80\xff",     2); break;
  case CL:   append_bytes(s, "\x80\xf9",     2); break;
  case CH:   append_bytes(s, "\x80\xfd",     2); break;
  case DL:   append_bytes(s, "\x80\xfa",     2); break;
  case DH:   append_bytes(s, "\x80\xfe",     2); break;
  case SIL:  append_bytes(s, "\x40\x80\xfe", 3); break;
  case DIL:  append_bytes(s, "\x40\x80\xff", 3); break;
  case BPL:  append_bytes(s, "\x40\x80\xfd", 3); break;
  case SPL:  append_bytes(s, "\x40\x80\xfc", 3); break;
  case R8B:  append_bytes(s, "\x41\x80\xf8", 3); break;
  case R9B:  append_bytes(s, "\x41\x80\xf9", 3); break;
  case R10B: append_bytes(s, "\x41\x80\xfa", 3); break;
  case R11B: append_bytes(s, "\x41\x80\xfb", 3); break;
  case R12B: append_bytes(s, "\x41\x80\xfc", 3); break;
  case R13B: append_bytes(s, "\x41\x80\xfd", 3); break;
  case R14B: append_bytes(s, "\x41\x80\xfe", 3); break;
  case R15B: append_bytes(s, "\x41\x80\xff", 3); break;
  }

  da_append(s, cmp);
}

ELF_DEF void gen_push_8(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_pop_8(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_jmp_r_8(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

ELF_DEF void gen_call_r_8(Bytes *s, Register r) {
  // Doesn't exist apparently?
}

#endif // ELFGEN_IMPLEMENTATION
