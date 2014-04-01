/*
 * Universal wrapper API for a message digest function
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 */

#ifndef MD_H
#define MD_H

#include <string.h>

#define MD_RIPEMD160

#ifdef MD_RIPEMD160
#define MD_LEN 20
#define MD_BUFLEN 64
#endif

typedef struct {
  unsigned char md[MD_LEN];           /* internal status of hash function */
  unsigned char buf[MD_BUFLEN];       /* buffer for stream-like interface */
  unsigned long length_lo, length_hi;     /* number of bits hashed so far */
} md_state;

/* prototypes */

void md_init(md_state *md);
void md_add(md_state *md, const void *src, size_t len);
void md_close(md_state *md, unsigned char *result);
int md_selftest(void);

#endif
