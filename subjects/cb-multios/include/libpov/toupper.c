#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

int cgc_isalpha(int c);

vvdump_ignore
int cgc_toupper(int c) {
   if (cgc_isalpha(c)) {
      return c & ~0x20;
   }
   return c;
}

vvdump_ignore
int cgc_tolower(int c) {
   if (cgc_isalpha(c)) {
      return c | 0x20;
   }
   return c;
}

