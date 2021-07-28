
#ifndef NULL
#define NULL ((void*)0)
#endif

#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

typedef unsigned int cgc_size_t;

vvdump_ignore
char *cgc_strchr(const char *s, int c) {
   while (*s && *s != c) {s++;}
   return (char*)(*s ? s : (c ? NULL : s));
}
