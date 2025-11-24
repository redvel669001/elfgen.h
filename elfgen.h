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

// ************************* 64-bits *************************
ELF_DEF void gen_add_64_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_64_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_64_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_64_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_64(Bytes *s, Register r);
ELF_DEF void gen_dec_64(Bytes *s, Register r);

ELF_DEF void gen_imul_64_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_64_long_form(Bytes *s, Register r, size_t mul);

#define gen_little_endian_64(s, big_endian) gen_little_endian(s, big_endian, 4)

// ************************* 32-bits *************************
ELF_DEF void gen_add_32_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_32_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_32_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_32_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_32(Bytes *s, Register r);
ELF_DEF void gen_dec_32(Bytes *s, Register r);

ELF_DEF void gen_imul_32_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_32_long_form(Bytes *s, Register r, size_t mul);

#define gen_little_endian_32(s, big_endian) gen_little_endian(s, big_endian, 4)

// ************************* 16-bits *************************
ELF_DEF void gen_add_16_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_16_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_16_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_16_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_inc_16(Bytes *s, Register r);
ELF_DEF void gen_dec_16(Bytes *s, Register r);

ELF_DEF void gen_imul_16_short_form(Bytes *s, Register r, char mul);
ELF_DEF void gen_imul_16_long_form(Bytes *s, Register r, size_t mul);

#define gen_little_endian_16(s, big_endian) gen_little_endian(s, big_endian, 2)

// ************************* 8-bits *************************
ELF_DEF void gen_add_8(Bytes *s, Register r, char add);
ELF_DEF void gen_sub_8(Bytes *s, Register r, char sub);

ELF_DEF void gen_inc_8(Bytes *s, Register r);
ELF_DEF void gen_dec_8(Bytes *s, Register r);

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

// ************************* 64-bits *************************
ELF_DEF void gen_add_64_short_form(Bytes *s, Register r, char add) {
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

ELF_DEF void gen_add_64_long_form(Bytes *s, Register r, size_t add) {
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

ELF_DEF void gen_sub_64_short_form(Bytes *s, Register r, char sub) {
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

ELF_DEF void gen_sub_64_long_form(Bytes *s, Register r, size_t sub) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x2d",      2); break;
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

ELF_DEF void gen_imul_64_short_form(Bytes *s, Register r, char mul) {
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

ELF_DEF void gen_imul_64_long_form(Bytes *s, Register r, size_t mul) {
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

// ************************* 32-bits *************************
ELF_DEF void gen_add_32_short_form(Bytes *s, Register r, char add) {
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

ELF_DEF void gen_add_32_long_form(Bytes *s, Register r, size_t add) {
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

// ************************* 16-bits *************************
ELF_DEF void gen_add_16_short_form(Bytes *s, Register r, char add) {
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

ELF_DEF void gen_add_16_long_form(Bytes *s, Register r, size_t add) {
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

ELF_DEF void gen_sub_16_short_form(Bytes *s, Register r, char sub) {
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

ELF_DEF void gen_sub_16_long_form(Bytes *s, Register r, size_t sub) {
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

ELF_DEF void gen_imul_16_short_form(Bytes *s, Register r, char mul) {
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

ELF_DEF void gen_imul_16_long_form(Bytes *s, Register r, size_t mul) {
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

// ************************* 8-bits *************************
ELF_DEF void gen_add_8(Bytes *s, Register r, char add) {
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

ELF_DEF void gen_sub_8(Bytes *s, Register r, char sub) {
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

#endif // ELFGEN_IMPLEMENTATION
