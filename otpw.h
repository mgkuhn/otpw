/*
 * One-time password login capability
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 */

#ifndef OTPW_H
#define OTPW_H

#include <pwd.h>
#include <sys/types.h>
#include "conf.h"
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
  char challenge[81];        /* print this string before "Password:" */
  int passwords;             /* number of req. passwords (0, 1, OTPW_MULTI) */
  int locked;                /* flag, whether lock has been set */
  int entries;               /* number of entries in OTPW_FILE */
  int pwlen;                 /* number of characters in password */
  int remaining;             /* number of remaining unused OTPW_FILE entries */
  uid_t uid;                 /* effective uid for OTPW_FILE/OTPW_LOCK access */
  gid_t gid;                 /* effective gid for OTPW_FILE/OTPW_LOCK access */
  int selection[OTPW_MULTI]; /* positions of the requested passwords */
  char hash[OTPW_MULTI][OTPW_HLEN + 1];
                             /* base64 hash value of the requested passwords */
  int flags;                 /* 1 : debug messages, 2: no locking */
};

/*
 * After the user has entered a login name and has requested OTPW
 * authentication and after and you have retrieved the password
 * database entry *user for this name, call otpw_prepare().
 * A string with the challenge text that has to be presented to the
 * user before the password can be entered will be found in
 * ch->challenge afterwards, but ch->challenge[0] == 0 if one-time
 * password authentication is not possible at this time. The struct *ch
 * has to be given later to otpw_verify(). We do a chdir() to the user's
 * home directory here, and otpw_verify() will expect the
 * current working directory to still be there, so don't change it
 * between the two calls. After a successful login, check whether
 * ch->entries > 2 * ch->remaining and remind the user to generate
 * new passwords if so.
 */

void otpw_prepare(struct challenge *ch, struct passwd *user, int flags);

/*
 * After the one-time password has been entered, call optw_verify()
 * to find out whether the password was ok. The parameters are
 * the challenge structure filled previously by otpw_prepare() and
 * the entered password. Accept the user iff the return value is OTPW_OK.
 *
 * IMPORTANT: If otpw_prepare() has returned a non-empty challenge
 * string, then you must call otpw_verify(), even if the login was
 * aborted and you are not any more interested in the result. Otherwise
 * a stale lock might remain.
 */

int otpw_verify(struct challenge *ch, char *password);

#endif
