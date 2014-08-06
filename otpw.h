/*
 * One-time password login library
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 */

#ifndef OTPW_H
#define OTPW_H

#include <pwd.h>
#include <sys/types.h>
#include "md.h"

/* password authentication results (returned by otpw_verify()) */

#define OTPW_OK     0   /* this was the correct password */
#define OTPW_WRONG  1   /* this was the wrong password */
#define OTPW_ERROR  2   /* user has not registered for the OTPW service
			 * or something else went wrong */

/* flags for otpw_prepare() */

#define OTPW_DEBUG   1  /* output debugging messages via DEBUG_LOG macro */
#define OTPW_NOLOCK  2  /* disable locking, never create or check OTPW_LOCK */

/*
 * A data structure used by otpw_prepare to return the
 * selected challenge 
 */

struct challenge {
  char challenge[81];   /* print this string before "Password:" */
  int passwords;        /* number of req. passwords (0, 1, otpw_multi) */
  int locked;           /* flag, whether lock has been set */
  int entries;          /* number of entries in OTPW file */
  int pwlen;            /* number of characters in password */
  int challen;          /* number of characters in challenge string */
  int hlen;             /* number of characters in hash value */
  int remaining;        /* number of remaining unused OTPW file entries */
  uid_t uid;            /* effective uid for OTPW file/lock access */
  gid_t gid;            /* effective gid for OTPW file/lock access */
  int *selection;       /* position of the otpw_multi requested passwords */
  char **hash;          /* base64 hash values of the otpw_multi requested
			   passwords, each otpw_hlen+1 bytes long */
  int flags;            /* 1 : debug messages, 2: no locking */
  char *filename;       /* path of .otpw file (malloc'ed) */
  char *lockfilename;   /* path of .optw.lock file (malloc'ed) */
};

/*
 * Call otpw_prepare() after the user has entered their login name and
 * has requested OTPW authentication, and after and you have retrieved
 * their password database entry *user. After the call, ch->challenge
 * will contain a string that you have to present to the user before
 * they can enter the password. If ch->challenge[0] == 0 then one-time
 * password authentication is not possible at this time. Once you have
 * received the password, pass it to otpw_verify() along with the same
 * struct *ch used here.
 */

void otpw_prepare(struct challenge *ch, struct passwd *user, int flags);

/*
 * After the one-time password has been entered, call optw_verify() to
 * find out whether the password was ok. The parameters are the
 * challenge structure filled previously by otpw_prepare() and the
 * password that the user has provided ('\0' terminated). Accept the
 * user if and only if the return value is OTPW_OK.
 *
 * IMPORTANT: If otpw_prepare() returned a non-empty challenge string
 * (ch->challenge[0] != 0), then you MUST call otpw_verify(), even if
 * the login was aborted and you are not any more interested in the
 * result. Otherwise a stale lock might remain.
 *
 * After a successful login, check whether ch->entries > 2 *
 * ch->remaining and remind the user to generate new passwords if
 * so.
 */

int otpw_verify(struct challenge *ch, char *password);

/* some global variables with configuration options */

extern char *otpw_file;
extern char *otpw_locksuffix;
extern int otpw_multi;
extern int otpw_hlen;
extern char *otpw_magic;
extern double otpw_locktimeout;
extern struct passwd *otpw_pseudouser;

#endif
