/*
 * One-time password generator
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: otpw-gen.c,v 1.6 2003-06-24 20:41:59 mgk25 Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <termios.h>
#include "conf.h"
#include "md.h"


#define NL "\r\n"               /* new line sequence in password list output */
#define HEADER_LINES  4       /* lines printed in addition to password lines */
#define MAX_PASSWORDS 1000                /* maximum length of password list */
#define CHALLEN 3                       /* number of characters in challenge */
#define HBUFLEN (CHALLEN + OTPW_HLEN + 1)

/* add the output and time of a shell command to message digest */

void gurgle(md_state *mdp, char *command)
{
  FILE *f;
  char buf[128];
  long len = 0, l;
  struct timeval t;

  f = popen(command, "r");
  gettimeofday(&t, NULL);
  md_add(mdp, (unsigned char *) &t, sizeof(t));
  if (!f) {
    fprintf(stderr, "External entropy source command '%s'\n"
	    "(one of several) failed.\n", command);
    return;
  }
  while (!feof(f) && !ferror(f)) {
    len += l = fread(buf, 1, sizeof(buf), f);
    md_add(mdp, buf, l);
  }
  if (len == 0)
    fprintf(stderr, "External entropy source command '%s'\n"
	    "returned no output.\n", command);
#ifdef DEBUG
  else
    fprintf(stderr, "'%s' added %ld bytes.\n", command, len);
#endif
  pclose(f);
  gettimeofday(&t, NULL);
  md_add(mdp, (unsigned char *) &t, sizeof(t));
}


/* A random bit generator. Hashes together various sources of entropy
 * to provide a 16 byte high quality random seed */

/* Determine the initial start state of the random bit generator */

void rbg_seed(unsigned char *r)
{
  /* shell commands that provide high entropy output for RNG */
  char *entropy_cmds[] = {
    ENTROPY_CMDS
  };
  char *entropy_env[] = {
    ENTROPY_ENV
  };
  unsigned i;
  md_state md;
  struct {
    clock_t clk;
    pid_t pid;
    uid_t uid;
    pid_t ppid;
  } entropy;
  
  md_init(&md);

  /* get entropy via some shell commands */
  for (i = 0;  i < sizeof(entropy_env)/sizeof(char*); i++)
    putenv(entropy_env[i]);
  for (i = 0; i < sizeof(entropy_cmds)/sizeof(char*); i++)
    gurgle(&md, entropy_cmds[i]);

  /* other minor sources of entropy */
  entropy.clk = clock();
  entropy.uid = getuid();
  entropy.pid = getpid();
  entropy.ppid = getppid();

  md_add(&md, (unsigned char *) &entropy, sizeof(entropy));

  md_close(&md, r);
}


/* Determine the next random bit generator state */

void rbg_iter(unsigned char *r)
{
  md_state md;
  struct timeval t;

  md_init(&md);
  gettimeofday(&t, NULL);
  md_add(&md, (unsigned char *) &t, sizeof(t));
  md_add(&md, r, MD_LEN);
  md_add(&md, "AutomaGic", 9);  /* feel free to change this as a site key */
  md_close(&md, r);
}


/*
 * Transform the first 6*chars bits of the binary string v into a chars
 * character long string s. The encoding is a modification of the MIME
 * base64 encoding where characters with easily confused glyphs are
 * avoided (0 vs O, 1 vs. l vs. I).
 */

void conv_base64(char *s, const unsigned char *v, int chars)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk%mnopqrstuvwxyz"
    ":=23456789+/";
  int i, j;
  
  for (i = 0; i < chars; i++) {
    j = (i / 4) * 3;
    switch (i % 4) {
    case 0: *s++ = tab[  v[j]  >>2];                        break;
    case 1: *s++ = tab[((v[j]  <<4) & 0x30) | (v[j+1]>>4)]; break;
    case 2: *s++ = tab[((v[j+1]<<2) & 0x3c) | (v[j+2]>>6)]; break;
    case 3: *s++ = tab[  v[j+2]     & 0x3f];                break;
    }
  }
  *s++ = '\0';
}


int main(int argc, char **argv)
{
  char version[] = "One-Time Password Generator v 1.2 -- Markus Kuhn";
  char usage[] = "%s\n\n%s [options] | lpr\n"
    "\nOptions:\n\n"
    "\t-h <int>\tnumber of output lines (default 60)\n"
    "\t-w <int>\tmax width of output lines (default 79)\n"
    "\t-s <int>\tlength of each one-time password (default 8)\n"
    "\t-f <filename>\tdestination file for hashes (default: ~/" OTPW_FILE
    ")\n\n";

  unsigned char r[MD_LEN], h[MD_LEN];
  md_state md;
  int i, j, k, l, m;
  struct passwd *pwd = NULL;
  FILE *f;
  char timestr[81], hostname[81], password1[81], password2[81];
  char *fnout = NULL;
  struct termios term, term_old;
  int stdin_is_tty = 0;
  int width = 79, rows = 60 - HEADER_LINES, pwlen = 8;
  int cols, spaces;
  time_t t;
  char *hbuf;

  assert(md_selftest() == 0);
  assert(OTPW_HLEN * 6 < MD_LEN * 8);
  assert(OTPW_HLEN >= 8);

  /* read command line arguments */
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-')
      for (j = 1; j > 0 && argv[i][j] != 0; j++)
        switch (argv[i][j]) {
        case 'h':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify number of lines output after option -h "
		    "(e.g., \"-h 50\")!\n");
	    exit(1);
	  }
	  rows = atoi(argv[i]) - HEADER_LINES;
	  if (rows <= 0) {
	    fprintf(stderr, "Specify not less than %d lines "
		    "(to leave room for header)!\n", HEADER_LINES + 1);
	    exit(1);
	  }
          j = -1;
          break;
        case 'w':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify maximum line length after option -w "
		    "(e.g., \"-l 50\")!\n");
	    exit(1);
	  }
	  width = atoi(argv[i]);
	  if (width < 64) {
	    fprintf(stderr, "Specify not less than 64 character "
		    "wide lines!\n");
	    exit(1);
	  }
          j = -1;
          break;
        case 's':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify password length after option -s "
		    "(e.g., \"-s 8\")!\n");
	    exit(1);
	  }
	  pwlen = atoi(argv[i]);
	  if (pwlen < 4 || pwlen > (MD_LEN * 4) / 6) {
	    fprintf(stderr, "Password length must be in range 4 to %d!\n",
		    (MD_LEN * 4) / 6);
	    exit(1);
	  }
          j = -1;
          break;
        case 'f':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify filename after option -f!\n");
	    exit(1);
	  }
          fnout = argv[i];
	  j = -1;
          break;
	default:
          fprintf(stderr, usage, version, argv[0]);
          exit(1);
        }
    else {
      fprintf(stderr, usage, version, argv[0]);
      exit(1);
    }
  }

  spaces = (pwlen + 3) / 4;
  cols = (width + 2) / (CHALLEN + 1 + pwlen + spaces + 1);
  if (rows * cols > 1000)
    rows = 1000 / cols;

  if (!fnout) {
    fnout = OTPW_FILE;
    pwd = getpwuid(getuid());
    if (!pwd) {
      fprintf(stderr, "Can't access your password database entry!\n");
      exit(1);
    }
    /* change to home directory */
    chdir(pwd->pw_dir);
  }

  fprintf(stderr, "Generating random seed ...\n");
  rbg_seed(r);

  fprintf(stderr,
    "If your paper password list is stolen, the thief should not gain\n"
    "access to your account with this information alone. Therefore, you\n"
    "need to memorize and enter below a prefix password. You will have to\n"
    "enter that each time directly before entering the one-time password\n"
    "(on the same line).\n\n"
    "When you log in, a three-digit password number will be displayed.  It\n"
    "identifies the one-time password on your list that you have to append\n"
    "to the prefix password. If another login to your account is in progress\n"
    "at the same time, several password numbers may be shown and all\n"
    "corresponding passwords have to be appended after the prefix\n"
    "password. Best generate a new password list when you have used up half\n"
    "of the old one.\n\n");

  fprintf(stderr, "Enter new prefix password: ");
  /* disable echo if stdin is a terminal */
  if (!tcgetattr(fileno(stdin), &term)) {
    stdin_is_tty = 1;
    term_old = term;
    term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(fileno(stdin), TCSAFLUSH, &term)) {
      perror("tcsetattr");
      exit(1);
    }
  }
  fgets(password1, sizeof(password1), stdin);
  fprintf(stderr, "\nReenter prefix password: ");
  fgets(password2, sizeof(password2), stdin);
  if (stdin_is_tty)
    tcsetattr(fileno(stdin), TCSANOW, &term_old);
  if (strcmp(password1, password2)) {
    fprintf(stderr, "\nThe two entered passwords were not identical!\n");
    exit(1);
  }
  /* remove newline = last character */
  if (*password1)
    password1[strlen(password1)-1] = 0;

  fprintf(stderr, "\n\nCreating '%s'.\n", fnout);
  f = fopen(OTPW_TMP, "w");
  if (!f) {
    fprintf(stderr, "Can't write to '" OTPW_TMP);
    perror("'");
    exit(1);
  }
  chmod(OTPW_TMP, S_IRUSR | S_IWUSR);

  /* write magic code for format identification */
  fprintf(f, OTPW_MAGIC);
  fprintf(f, "%d %d %d %d\n", rows * cols, CHALLEN, OTPW_HLEN,
	  pwlen);
  
  fprintf(stderr, "Generating new one-time passwords ...\n\n");

  /* print header that uniquely identifies this password list */
  time(&t);
  strftime(timestr, 80, "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
  printf("OTPW list generated %s", timestr);
  if (!gethostname(hostname, sizeof(hostname)))
    printf(" on %.*s", (int) sizeof(hostname), hostname);
  printf(NL NL);
  
  hbuf = malloc(rows * cols * HBUFLEN);
  if (!hbuf) {
    fprintf(stderr, "Memory allocation error!\n");
    exit(1);
  }

  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      k = j * rows + i;
      /* generate new password */
      md_init(&md);
      rbg_iter(r);
      md_add(&md, password1, strlen(password1));
      conv_base64(password2, r, pwlen);
      md_add(&md, password2, pwlen);
      /* output challenge */
      printf("%03d ", k);
      /* output password, insert spaces every 3-4 chars (Bresenham's alg.) */
      m = 0;
      for (l = 0; l < pwlen; l++) {
	putchar(password2[l]);
	if ((m += spaces) >= pwlen && l != pwlen - 1) {
	  putchar(' ');
	  m -= pwlen;
	}
      }
      printf(j == cols - 1 ? NL : "  ");
      /* hash password and save result */
      md_close(&md, h);
      sprintf(hbuf + k * HBUFLEN, "%0*d", CHALLEN, k);
      conv_base64(hbuf + k*HBUFLEN + CHALLEN, h, OTPW_HLEN);
    }
  }

  /* paranoia RAM scrubbing (note that we can't scrub stdout/stdin portably) */
  md_init(&md);
  md_add(&md,
	 "Always clean up all memory that was in contact with secrets!!!!!!",
	 65);
  md_close(&md, h);
  memset(password1, 0xaa, sizeof(password1));
  memset(password2, 0xaa, sizeof(password2));

  /* output all hash values in random permutation order */
  for (k = rows * cols - 1; k >= 0; k--) {
    rbg_iter(r);
    i = k > 0 ? (*(unsigned *) r) % k : 0;
    fprintf(f, "%s\n", hbuf + i*HBUFLEN);
    memcpy(hbuf + i*HBUFLEN, hbuf + k*HBUFLEN, HBUFLEN);
  }

  printf(NL "%*s" NL, (cols*(CHALLEN + pwlen + spaces + 2) - 1)/2 + 49/2,
	 "!!! REMEMBER: Enter the PREFIX PASSWORD first !!!");

  fclose(f);
  if (rename(OTPW_TMP, fnout)) {
    fprintf(stderr, "Can't rename '" OTPW_TMP "' to '%s", fnout);
    perror("'");
    exit(1);
  }
  /* if we overwrite OTPW_FILE, then any remaining lock is now meaningless */
  if (pwd)
    unlink(OTPW_LOCK);

  return 0;
}
