/*
 * One-time password login capability
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: otpw.c,v 1.5 2003-06-20 13:58:58 mgk25 Exp $
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "otpw.h"
#include "conf.h"
#include "md.h"

#ifndef DEBUG_LOG
#  if DEBUG
#    define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__); fputc('\n', stderr)
#  else
#    define DEBUG_LOG(...)
#  endif
#endif

/*
 * A random bit generator. Hashes together some quick sources of entropy
 * to provide some reasonable random seed. (High entropy is not security
 * critical here.)
 */

void rbg_seed(unsigned char *r)
{
  int devrandom;
  char rbs[MD_LEN];
  md_state md;
  struct {
    clock_t clk;
    pid_t pid;
    uid_t uid;
    pid_t ppid;
    struct timeval t;
  } entropy;
  
  md_init(&md);

  /* read out kernel random number generator device if there is one */
  devrandom = open("/dev/urandom", O_RDONLY);
  if (devrandom >= 0) {
    read(devrandom, rbs, sizeof(rbs));
    md_add(&md, rbs, sizeof(rbs));
    close(devrandom);
  }

  /* other minor sources of entropy */
  entropy.clk = clock();
  entropy.uid = getuid();
  entropy.pid = getpid();
  entropy.ppid = getppid();
  gettimeofday(&entropy.t, NULL);
  md_add(&md, (unsigned char *) &entropy, sizeof(entropy));

  md_close(&md, r);
}


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


void conv_base64(char *s, const unsigned char *v, int groups)
{
  const char tab[] =
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


void otpw_prepare(struct challenge *ch, struct passwd *user)
{
  FILE *f = NULL;
  int i, j;
  int locked, count, repeat;
  int olduid = -1;
  int oldgid = -1;
  char line[81];
  unsigned char r[MD_LEN];
  struct stat lbuf;
  char (*hash)[13] = NULL;   /* list of hashed passwords */

  if (!ch) {
    DEBUG_LOG("!ch");
    return;
  }
  ch->passwords = 0;
  ch->remaining = -1;
  ch->entries = -1;
  ch->locked = 0;
  ch->challenge[0] = 0;
  if (!user) {
    DEBUG_LOG("No password database entry provided!");
    return;
  }
  ch->uid = user->pw_uid;
  ch->gid = user->pw_gid;
  
  /* set effective uid/gui temporarily */
  olduid = geteuid();
  oldgid = getegid();
  if (setegid(ch->gid))
    DEBUG_LOG("Failed to change egid %d -> %d", oldgid, ch->gid);
  if (seteuid(ch->uid))
    DEBUG_LOG("Failed to change euid %d -> %d", olduid, ch->uid);

  /* open password file */
  if (chdir(user->pw_dir)) {
    DEBUG_LOG("chdir(\"%s\"): %s", user->pw_dir, strerror(errno));
    goto cleanup;
  }
  if (!(f = fopen(OTPW_FILE, "r"))) {
    DEBUG_LOG("fopen(\"%s\", \"r\"): %s", user->pw_dir, strerror(errno));
    goto cleanup;
  }
  
  /* prepare random number generator */
  rbg_seed(r);

  /* check header */
  if (!fgets(line, sizeof(line), f) ||
      strcmp(line, OTPW_MAGIC) ||
      !fgets(line, sizeof(line), f)) {
    DEBUG_LOG("Header in '" OTPW_FILE "' wrong!");
    goto cleanup;
  }
  ch->entries = atoi(line);
  if (ch->entries < 1 || ch->entries > 999) {
    DEBUG_LOG("Number of entries (%d) out of allowed range!",
	      ch->entries);
    goto cleanup;
  }
  
  hash = (char (*)[13]) malloc(ch->entries * sizeof(char [13]));
  if (!ch) {
    DEBUG_LOG("malloc failed");
    return;
  }

  ch->remaining = 0;
  for (i = 0; i < ch->entries; i++) {
    if (!fgets(line, sizeof(line), f) ||
	sscanf(line, "%12s", hash[i]) != 1) {
      DEBUG_LOG("'" OTPW_FILE "' too short!");
      goto cleanup;
    }
    if (hash[i][0] != '-')
      ch->remaining++;
  }
  if (ch->remaining < 1) {
    DEBUG_LOG("No passwords left!");
    goto cleanup;
  }

  /* select challenge */
  count = 0;
  j = 0;
  do {
#if OTPW_RANDOM_CHALLENGE
    /* This truly random challenge is not a good idea since this gives
     * an attacker who knows one password quick access to all challenges */
    rbg_iter(r);
    j = *((unsigned int *) r) % ch->entries;
#else
    /* do a deterministic slightly pseudo-random search */
    j = (j + 17) % ch->entries;
#endif
  } while (hash[j][0] == '-' && count++ < 2 * ch->entries);
  while (hash[j][0] == '-')
    j = (j + 1) % ch->entries;
  sprintf(ch->challenge, "%03d", j);
  ch->selection[0] = j;
  strcpy(ch->hash[0], hash[j]);

  count = 0;
  do {
    repeat = 0;

    /* try to get a lock on this one */
    if (symlink(ch->challenge, OTPW_LOCK) == 0) {
      /* ok, we got the lock */
      ch->passwords = 1;
      ch->locked = 1;
      goto cleanup;
    }
    if (errno != EEXIST) {
      DEBUG_LOG("symlink(\"%s\", \"" OTPW_LOCK "\"): %s",
		ch->challenge, strerror(errno));
      ch->challenge[0] = 0;
      goto cleanup;
    }
    
    if (lstat(OTPW_LOCK, &lbuf) == 0) {
      if (time(NULL) - lbuf.st_mtime > 60 * 60 * 24) {
	/* remove a stale lock after 24h as the login should have timed out */
	unlink(OTPW_LOCK);
	repeat = 1;
      }
    } else if (errno == ENOENT)
      repeat = 1;
    else {
      DEBUG_LOG("lstat(\"" OTPW_LOCK "\", ...): %s", strerror(errno));
      ch->challenge[0] = 0;
      goto cleanup;
    }

  } while (repeat && ++count < 5);
  ch->challenge[0] = 0;

  /* ok, there is already a fresh lock, so someone is currently logging in */
  locked = -1;
  i = readlink(OTPW_LOCK, line, sizeof(line)-1);
  if (i > 0) {
    line[i] = 0;
    if (line[0] >= '0' && line[0] <= '9' &&
	line[1] >= '0' && line[1] <= '9' &&
	line[2] >= '0' && line[2] <= '9' &&
	line[3] == 0)
      locked = atoi(line);
    else {
      /* lock symlink seems to have been corrupted */
      DEBUG_LOG("Removing corrupt lock symlink.");
      unlink(OTPW_LOCK);
    }
  } else if (errno != ENOENT) {
    DEBUG_LOG("Could not read lock symlink.");
    goto cleanup;
  }

  /* now we generate OTPW_MULTI challenges */
  if (ch->remaining < OTPW_MULTI+1 || ch->remaining < 10) {
    DEBUG_LOG("%d remaining passwords are not enough for "
	    "multi challenge.", ch->remaining);
    goto cleanup;
  }
  while (ch->passwords < OTPW_MULTI &&
	 strlen(ch->challenge) < sizeof(ch->challenge) - 10) {
    count = 0;
    /* random scan for remaining password */
    do {
      /* pick a random entry */
      rbg_iter(r);
      j = *((unsigned int *) r) % ch->entries;
      /* test whether we had this one already */
      repeat = 0;
      for (i = 0; i < ch->passwords; i++)
	repeat |= (j == ch->selection[i]);
    } while ((hash[j][0] == '-' || j == locked || repeat) &&
	     count++ < 2 * ch->entries);
    /* fallback scan for remaining password */
    while (hash[j][0] == '-' || j == locked)
      j = (j + 1) % ch->entries;
    /* add password j to multi challenge */
    sprintf(ch->challenge + strlen(ch->challenge), "%s%03d",
	    ch->passwords ? "/" : "", j);
    strcpy(ch->hash[ch->passwords], hash[j]);
    ch->selection[ch->passwords++] = j;
    hash[j][0] = '-';
  }

cleanup:
  if (f)
    fclose(f);
  /* restore uid/gid */
  if (olduid != -1)
    if (seteuid(olduid))
      DEBUG_LOG("Failed when trying to change euid back to %d", olduid);
  if (oldgid != -1)
    if (setegid(oldgid))
      DEBUG_LOG("Failed when trying to change egid back to %d", oldgid);
  if (hash)
    free(hash);

  return;
}


int otpw_verify(struct challenge *ch, char *password)
{
  FILE *f = NULL;
  int result = OTPW_ERROR;
  int i, j = 0, l;
  int entries;
  int deleted, clear;
  int olduid = -1;
  int oldgid = -1;
  char otpw[OTPW_MULTI][OTPW_GROUPS * 4];
  char line[81];
  unsigned char h[MD_LEN];
  md_state md;

  if (!ch) {
    DEBUG_LOG("!ch");
    return OTPW_ERROR;
  }

  if (!password || ch->passwords < 1 ||
      ch->passwords > OTPW_MULTI) {
    DEBUG_LOG("otpw_verify(): Invalid parameters or no challenge issued.");
    goto cleanup;
  }
  
  /*
   * Scan in the one-time passwords, eliminating any spurious characters
   * (such as whitespace, control characters) that might have been added
   * accidentally
   */
  l = strlen(password) - 1;
  memset(otpw, 0, OTPW_GROUPS * 4 * ch->passwords);
  for (i = ch->passwords-1; i >= 0 && l >= 0; i--) {
    for (j = OTPW_GROUPS * 4 - 1; j >= 0 && l >= 0; j--) {
      while (!otpw[i][j] && l >= 0) {
	/* remove DEL/BS characters */
	deleted = 0;
	while (l >= 0 &&
	       (password[l] == 8 || password[l] == 127 || deleted > 0)) {
	  if (password[l] == 8 || password[l] == 127)
	    deleted++;
	  else
	    deleted--;
	  l--;
	}
	if (l < 0) break;
	if (password[l] == 'l' || password[l] == '1' || password[l] == '|')
	  otpw[i][j] = 'I';
	else if (password[l] == '0')
	  otpw[i][j] = 'O';
	else if (password[l] == '\\')
	  otpw[i][j] = '/';
	else if ((password[l] >= 'A' && password[l] <= 'Z') ||
		 (password[l] >= 'a' && password[l] <= 'z') ||
		 (password[l] >= '2' && password[l] <= '9') ||
		 password[l] == ':' ||
		 password[l] == '%' ||
		 password[l] == '=' ||
		 password[l] == '+' ||
		 password[l] == '/')
	  otpw[i][j] = password[l];
	l--;
      }
    }
    DEBUG_LOG("Password %d = '%.*s'", i, OTPW_GROUPS * 4, otpw[i]);
  }
  if (i >= 0 || j >= 0) {
    DEBUG_LOG("Entered password was too short.");
    result = OTPW_WRONG;
    goto cleanup;
  }
  
  l++;  /* l is now the length of the prefix password */
  DEBUG_LOG("Prefix = '%.*s'", l, password);
  
  /* now compare all entered passwords */
  for (i = 0; i < ch->passwords; i++) {
    md_init(&md);
    /* feed prefix password into hash function */
    md_add(&md, password, l);
    /* feed one-time password into hash function */
    md_add(&md, otpw[i], OTPW_GROUPS * 4);
    /* transform hash result into the base64 form used in OTPW_FILE */
    md_close(&md, h);
    conv_base64(line, h, 3);
    DEBUG_LOG("hash(password): '%s', hash from file: '%s'",
	   line, ch->hash[i]);
    if (strcmp(line, ch->hash[i])) {
      DEBUG_LOG("Entered password did not match.");
      result = OTPW_WRONG;
      goto cleanup;
    }
  }

  /* ok, all passwords were correct */
  result = OTPW_OK;
  DEBUG_LOG("Entered password(s) are ok.");

  /* set effective uid/gid temporarily */
  olduid = geteuid();
  oldgid = getegid();
  if (setegid(ch->gid))
    DEBUG_LOG("Failed when trying to change egid %d -> %d", oldgid, ch->gid);
  if (seteuid(ch->uid))
    DEBUG_LOG("Failed when trying to change euid %d -> %d", olduid, ch->uid);

  /* Now overwrite the used passwords in OTPW_FILE */
  if (!(f = fopen(OTPW_FILE, "r+"))) {
    DEBUG_LOG("Failed getting write access to '" OTPW_FILE "': %s",
	      strerror(errno));
    goto writefail;
  }
  /* check header */
  if (!fgets(line, sizeof(line), f) ||
      strcmp(line, OTPW_MAGIC) ||
      !fgets(line, sizeof(line), f)) {
    DEBUG_LOG("Overwrite failed because of header mismatch.");
    goto writefail;
  }
  entries = atoi(line);
  if (entries < 1 || entries > 999) {
    DEBUG_LOG("Overwrite failed because of wrong number of entries.");
    goto writefail;
  }
  for (i = 0; i < entries; i++) {
    clear = 0;
    for (j = 0; j < ch->passwords; j++)
      if (ch->selection[j] == i)
	clear = 1;
    if (clear) {
      fseek(f, 0L, SEEK_CUR);
      fprintf(f, "------------\n");
      fseek(f, 0L, SEEK_CUR);
      ch->remaining--;
    } else
      if (!fgets(line, sizeof(line), f)) {
	DEBUG_LOG("Overwrite failed because of unexpected EOF.");
	goto writefail;
      }
  }
  goto cleanup;

 writefail:
  /* entered one-time passwords were correct, but overwriting them failed */
  if (ch->passwords == 1) {
    /* for a single password, permit login, but keep lock in place */
    DEBUG_LOG("Keeping lock on password.");
    ch->locked = 0; /* supress removal of lock */
  }

 cleanup:
  if (f)
    fclose(f);
  /* remove lock */ 
  if (ch->locked)
    unlink(OTPW_LOCK);
  /* restore uid/gid */
  if (olduid != -1)
    if (seteuid(olduid))
      DEBUG_LOG("Failed when trying to change euid back to %d", olduid);
  if (oldgid != -1)
    if (setegid(oldgid))
      DEBUG_LOG("Failed when trying to change egid back to %d", oldgid);
  /* make sure, we are not called a second time */
  ch->passwords = 0;

  return result;
}
