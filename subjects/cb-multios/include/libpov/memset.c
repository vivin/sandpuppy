#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

vvdump_ignore
void *cgc_memset(void *dst, int c, unsigned int n) {
   char *d = (char*)dst;
   while (n--) {*d++ = (char)c;}
   return dst;
}

