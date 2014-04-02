/*
 * One-time password login library
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
 * Call otpw_prepare() after the user has entered their login name and
 * has requested OTPW authentication, and after and you have retrieved
 * their password database entry *user. After the call, ch->challenge
 * will contain a string that you have to present to the user before
 * they can enter the password. If ch->challenge[0] == 0 then one-time
 * password authentication is not possible at this time. Once you have
 * received the password, pass it to otpw_verify() along with the same
 * struct *ch used here.
 *
 * This function performs a chdir() to the user's home directory, and
 * otpw_verify() expects the current working directory to still be
 * there, so do not change it between these two calls.
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

#endif
