/*
 * One-time password generator
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: otpw-gen.c,v 1.5 2003-06-20 08:36:48 mgk25 Exp $
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
 * Transform a binary string of groups*3 bytes length into an ASCII
 * string of groups*4 characters. The encoding is a modification of
 * the MIME base64 encoding where characters with easily confused
 * glyphs are avoided (0 vs O, 1 vs. 1 vs. I).
 */

void conv_base64(char *s, const unsigned char *v, int groups)
{
  static const char tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk%mnopqrstuvwxyz"
    ":=23456789+/";
  int i;
  
  for (i = 0; i < groups; i++)
    sprintf(s+4*i, "%c%c%c%c",
	    tab[v[i*3]>>2],
	    tab[((v[i*3]<<4) & 0x30) | (v[i*3+1]>>4)],
	    tab[((v[i*3+1]<<2) & 0x3c) | (v[i*3+2]>>6)],
	    tab[v[i*3+2] & 0x3f]);
}


int main(int argc, char **argv)
{
  char version[] = "Generate New One-Time Passwords v 1.1 -- Markus Kuhn";
  char usage[] = "%s\n\n%s [options] | lpr\n"
    "\nOptions:\n\n"
    "\t-l <int>\tnumber of output lines (default 60)\n"
    "\t-n <int>\tnumber of new passwords (overrides -l)\n"
    "\t-f <filename>\tdestination file for hashes (default: ~/" OTPW_FILE
    ")\n\n";

  unsigned char r[MD_LEN], h[MD_LEN];
  md_state md;
  int i, j, k;
  struct passwd *pwd = NULL;
  FILE *f;
  char timestr[81], hostname[81], password1[81], password2[81];
  char *fnout = NULL;
  struct termios term, term_old;
  int stdin_is_tty = 0;
  int pw_per_line = 80 / (5 + 5 * OTPW_GROUPS);
  int newotpws = 60 * pw_per_line;
  time_t t;

  assert(md_selftest() == 0);
  assert(OTPW_GROUPS * 24 < MD_LEN * 4);
  assert(OTPW_GROUPS > 0);
  assert(OTPW_MULTI > 0);

  /* read command line arguments */
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-')
      for (j = 1; j > 0 && argv[i][j] != 0; j++)
        switch (argv[i][j]) {
        case 'n':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify number of new passwords after option -n "
		    "(e.g., \"-n 50\")!\n");
	    exit(1);
	  }
          newotpws = atoi(argv[i]);
	  if (newotpws < 0 || newotpws > MAX_PASSWORDS) {
	    fprintf(stderr, "Specify not more than %d new passwords!\n",
		    MAX_PASSWORDS);
	    exit(1);
	  }
          j = -1;
          break;
        case 'l':
	  if (++i >= argc) {
	    fprintf(stderr, "Specify number of lines output after option -l "
		    "(e.g., \"-l 50\")!\n");
	    exit(1);
	  }
	  k = atoi(argv[i]);
	  if (k <= HEADER_LINES) {
	    fprintf(stderr, "Specify not less than %d lines "
		    "(to leave room for header)!\n", HEADER_LINES + 1);
	    exit(1);
	  }
          newotpws = (k - HEADER_LINES) * pw_per_line;
	  if (newotpws < 0 || newotpws > MAX_PASSWORDS) {
	    fprintf(stderr, "Specify not more than %d lines or %d "
		    "new passwords!\n",
		    (MAX_PASSWORDS + pw_per_line - 1) / pw_per_line
		    + HEADER_LINES, MAX_PASSWORDS);
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
    "to the prefix password. If another login to your account is in\n"
    "progress at the same time, %d password numbers will be shown and all\n"
    "corresponding passwords have to be appended after the prefix\n"
    "password. Best generate a new password list when you have used up half\n"
    "of the old one.\n\n", OTPW_MULTI);

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
  fprintf(f, "%04d\n", newotpws);
  
  fprintf(stderr, "Generating new one-time passwords ...\n\n");

  /* print header that uniquely identifies this password list */
  time(&t);
  strftime(timestr, 80, "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
  printf("OTPW list generated %s", timestr);
  if (!gethostname(hostname, sizeof(hostname)))
    printf(" on %.*s", (int) sizeof(hostname), hostname);
  printf(NL NL);
  
  for (i = 0; i < newotpws; i++) {
    md_init(&md);
    rbg_iter(r);
    md_add(&md, password1, strlen(password1));
    conv_base64(password2, r, OTPW_GROUPS);
    md_add(&md, password2, OTPW_GROUPS * 4);
    printf("%03d ", i);
    for (j = 0; j < OTPW_GROUPS; j++)
      printf("%.4s ", password2 + 4 * j);
    printf(i % pw_per_line == pw_per_line-1 ? NL : " ");
    md_close(&md, h);
    conv_base64(password2, h, 3);
    fprintf(f, "%s\n", password2);
  }

  /* paranoia RAM scrubbing (note that we can't scrub stdout/stdin portably) */
  md_init(&md);
  md_add(&md,
	 "Always clean up all memory that was in contact with secrets!!!!!!",
	 65);
  md_close(&md, h);
  memset(password1, 0xaa, sizeof(password1));
  memset(password2, 0xaa, sizeof(password2));

  if (newotpws % pw_per_line != 0)
    printf(NL);
  printf(NL "            !!! REMEMBER: Enter the PREFIX PASSWORD first !!!" NL);

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
