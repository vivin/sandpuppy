#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

vvdump_ignore
char *cgc_strcpy(char *dst, const char *src) {
   char *d = dst;
   while ((*d++ = *src++) != 0) {}
   return dst;
}

