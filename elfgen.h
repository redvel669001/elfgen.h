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
#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
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
  REGISTERS,
} Register;

typedef struct {
  char *items;
  size_t count;
  size_t capacity;
} Bytes;

ELF_DEF void append_bytes(Bytes *s, const char *bytes, size_t len);

ELF_DEF void gen_add_short_form(Bytes *s, Register r, char add);
ELF_DEF void gen_add_long_form(Bytes *s, Register r, size_t add);

ELF_DEF void gen_sub_short_form(Bytes *s, Register r, char sub);
ELF_DEF void gen_sub_long_form(Bytes *s, Register r, size_t sub);

ELF_DEF void gen_little_endian(Bytes *s, size_t big_endian, size_t len);

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

ELF_DEF void gen_add_short_form(Bytes *s, Register r, char add) {
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

ELF_DEF void gen_add_long_form(Bytes *s, Register r, size_t add) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x05", 2);
  case RBX: append_bytes(s, "\x48\x81\xc3", 3);
  case RCX: append_bytes(s, "\x48\x81\xc1", 3);
  case RDX: append_bytes(s, "\x48\x81\xc2", 3);
  case RSI: append_bytes(s, "\x48\x81\xc6", 3);
  case RDI: append_bytes(s, "\x48\x81\xc7", 3);
  case RBP: append_bytes(s, "\x48\x81\xc5", 3);
  case RSP: append_bytes(s, "\x48\x81\xc4", 3);
  case R8:  append_bytes(s, "\x49\x81\xc0", 3);
  case R9:  append_bytes(s, "\x49\x81\xc1", 3);
  case R10: append_bytes(s, "\x49\x81\xc2", 3);
  case R11: append_bytes(s, "\x49\x81\xc3", 3);
  case R12: append_bytes(s, "\x49\x81\xc4", 3);
  case R13: append_bytes(s, "\x49\x81\xc5", 3);
  case R14: append_bytes(s, "\x49\x81\xc6", 3);
  case R15: append_bytes(s, "\x49\x81\xc7", 3);
  }

  gen_little_endian(s, add);
}

ELF_DEF void gen_sub_short_form(Bytes *s, Register r, char sub) {
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

ELF_DEF void gen_sub_long_form(Bytes *s, Register r, size_t sub) {
  switch (r) {
  case RAX: append_bytes(s, "\x48\x2d", 2); break;
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

  gen_little_endian(s, sub);
}

ELF_DEF void gen_little_endian(Bytes *s, size_t big_endian, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = (big_endian >> (i * 8)) & 0xFF;
    da_append(s, c);
  }
}

#endif // ELFGEN_IMPLEMENTATION
