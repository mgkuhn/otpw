/*
 * One-time password login capability
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 * Steven Murdoch <http://www.cl.cam.ac.uk/~sjm217/>
 *
 * Interface documentation:
 * 
 *  http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/pam_modules.html
 *  http://www.cl.cam.ac.uk/~mgk25/otpw.html
 *
 * Inspired by pam_pwdfile.c by Charl P. Botha <cpbotha@ieee.org>
 * and pam_unix/support.c (part of the standard PAM distribution)
 *
 * $Id: pam_otpw.c,v 1.2 2003-06-20 13:58:58 mgk25 Exp $
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#include <security/pam_modules.h>

#include "otpw.h"

#ifdef DEBUG
# define D(a) a
#else
# define D(a)
#endif

#define MODULE_NAME "pam_otpw"

/*
 * Output logging information to syslog
 *
 * pamh                     pointer to the PAM handle
 * priority, format, ...    passed on to (v)syslog
 *
 * (based on _log_err in pam_unix/support.c)
 */
void log_message(int priority, pam_handle_t *pamh, const char *format, ...)
{
  char *service = NULL;
  char logname[80];
  va_list args;

  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
  if (!service)
    service = "";
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);
  
  va_start(args, format);
  /* other PAM modules seem to use LOG_AUTH, which the man page
   * marked as deprecated, so we use LOG_AUTHPRIV instead */
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);  /* from BSD, not POSIX */
  va_end(args);
  closelog();
}

/*
 * Wrapper around conversation function (a callback function provided by
 * the PAM application to interact with the user)
 *
 * (based on converse in pam_unix/support.c)
 */
static int converse(pam_handle_t *pamh, int nargs,
		    struct pam_message **message,
		    struct pam_response **response)
{
  int retval;
  struct pam_conv *conv;
  
  /* get pointer to conversation function */
  retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh,"no conversation function: %s",
		pam_strerror(pamh, retval));
    return retval;
  }
  
  /* call conversation function */
  retval = conv->conv(nargs, (const struct pam_message **) message,
		      response, conv->appdata_ptr);

  if (retval != PAM_SUCCESS) {
    log_message(LOG_WARNING, pamh,"conversation function failed: %s",
		pam_strerror(pamh, retval));
  }

  return retval;          /* propagate error status */
}

/* we register cleanup() to be called when the app calls pam_end(),
 * to make sure that otpw_verify() gets a chance to remove locks */
static void cleanup(pam_handle_t *pamh, void *data, int err)
{
  D(log_message(LOG_DEBUG, pamh,"cleanup() called, data=%p, err=%d",
		data, err));
  if (((struct challenge *) data)->passwords)
    otpw_verify((struct challenge *) data, "entryaborted");
  free(data);
}

/*
 * Issue password prompt with challenge and receive response from user
 * 
 * (based on _set_auth_tok from pam_pwdfile.c, originally based
 * on pam_unix/support.c but that no longer seems to exist)
 */
static int get_response(pam_handle_t *pamh, char *challenge)
{
  int retval;
  volatile char *p;
  struct pam_message msg, *pmsg[1];
  struct pam_response *resp;
  char message[81];

  /* format password prompt */
  snprintf(message, sizeof(message), "Password %s: ", challenge);

  /* set up conversation call */
  pmsg[0] = &msg;
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = message;
  resp = NULL;
  
  /* call conversation function */
  if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS) {
    /* converse has already output a warning log message here */
    return retval;
  }

  /* error handling (just to be safe) */
  if (!resp) {
    log_message(LOG_WARNING, pamh, "get_response(): resp==NULL");
    return PAM_CONV_ERR;
  }
  if (!resp[0].resp) {
    log_message(LOG_WARNING, pamh, "get_response(): resp[0].resp==NULL");
    free(resp);
    return PAM_CONV_ERR;
  }

  /* store response as PAM item */
  pam_set_item(pamh, PAM_AUTHTOK, resp[0].resp);
  /* sanitize and free buffer */
  for (p = resp[0].resp; *p; p++)
    *p = 0;
  free(resp[0].resp);
  free(resp);

  return PAM_SUCCESS;
}

/*
 * Display a notice (err==0) or error message (err==1) to the user
 */
static int display_notice(pam_handle_t *pamh, int err, char *format, ...)
{
  int retval;
  struct pam_message msg, *pmsg[1];
  struct pam_response *resp;
  char message[1024];
  va_list args;

  /* format message */
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  /* set up conversation call */
  pmsg[0] = &msg;
  msg.msg_style = err ? PAM_ERROR_MSG : PAM_TEXT_INFO /* PAM_TEXT_INFO */;
  msg.msg = message;
  resp = NULL;
  
  /* call conversation function */
  if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS) {
    /* converse has already output a warning log message here */
    return retval;
  }

  /* memory wants to be free */
  if (resp) {
    if (resp[0].resp)
      free(resp[0].resp);
    free(resp);
  }

  return PAM_SUCCESS;
}


/* provided entry point for auth service */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
  int retval;
  const char *username;
  char *password;
  struct passwd *pwd;
  struct challenge *ch = NULL;

  D(log_message(LOG_DEBUG, pamh, "pam_sm_authenticate called"));
  
  /* ignore arguments */
  (void) flags;
  (void) argc;
  (void) argv;

  /* get user name */
  retval = pam_get_user(pamh, &username, "login: ");
  if (retval == PAM_CONV_AGAIN)
    return PAM_INCOMPLETE;
  else if (retval != PAM_SUCCESS) {
    log_message(LOG_NOTICE, pamh, "no username provided");
    return PAM_USER_UNKNOWN;
  }
  
  /* DEBUG */
  D(log_message(LOG_DEBUG, pamh, "username is %s", username));
  D(log_message(LOG_DEBUG, pamh, "uid=%d, euid=%d, gid=%d, egid=%d",
		getuid(), geteuid(), getgid(), getegid()));

  /* consult POSIX password database (to find homedir, etc.) */
  pwd = getpwnam(username);
  if (!pwd) {
    log_message(LOG_NOTICE, pamh, "username not found");
    return PAM_USER_UNKNOWN;
  }

  /*
   * Make sure that otpw_verify() is always called to clean up locks,
   * even if the connection is aborted while we are in get_response()
   * or something else goes wrong.
   */
  ch = calloc(1, sizeof(struct challenge));
  if (!ch)
    return PAM_AUTHINFO_UNAVAIL;
  retval = pam_set_data(pamh, MODULE_NAME":ch", ch, cleanup);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "pam_set_data() failed");
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* prepare OTPW challenge */
  otpw_prepare(ch, pwd);

  D(log_message(LOG_DEBUG, pamh, "challenge: %s", ch->challenge));
  if (ch->passwords < 1) {
    /* it seems OTPW might not have been set up or has exhausted keys,
       perhaps explain here in info msg hot to "man newpass" */
    log_message(LOG_NOTICE, pamh, "OTPW not set up for user %s", username);
    return PAM_AUTHINFO_UNAVAIL;
  }

  /* Issue challenge, get response */
  retval = get_response(pamh, ch->challenge);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh,"get_response() failed: %s",
		pam_strerror(pamh, retval));
    return PAM_AUTHINFO_UNAVAIL;
  }
  
  retval = pam_get_item(pamh, PAM_AUTHTOK, (void *)&password);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "auth token not found");
    return PAM_AUTHINFO_UNAVAIL;
  }
   
  if (!password) {
    /* NULL passwords are checked in get_response so this
     * point in the code should never be reached */
    log_message(LOG_ERR, pamh, "password==NULL (should never happen)");
    return PAM_AUTHINFO_UNAVAIL;
  }
   
  /* verify response */
  retval = otpw_verify(ch, password);
  if (retval == OTPW_OK) {
    D(log_message(LOG_DEBUG, pamh, "password matches"));
    return PAM_SUCCESS;
  } else if (retval == OTPW_WRONG) {
    log_message(LOG_NOTICE, pamh, "incorrect password from user %s", username);
    return PAM_AUTH_ERR;
  }
  log_message(LOG_ERR, pamh, "OTPW error %d for user %s", retval, username);

  return PAM_AUTHINFO_UNAVAIL;
}

/* another expected entry point */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, 
			      int argc, const char **argv)
{
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;

  D(log_message(LOG_DEBUG, pamh, "pam_sm_setcred called"));

  /* NOP */

  return PAM_SUCCESS;
}

/* this is called after the user has logged in */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, 
				   int argc, const char **argv)
{
  struct challenge *ch = NULL;
  int retval;

  (void) argc;
  (void) argv;

  D(log_message(LOG_DEBUG, pamh, "pam_sm_open_session called, flags=%d",
		flags));

  retval = pam_get_data(pamh, MODULE_NAME":ch", (const void **) &ch);
  if (retval != PAM_SUCCESS || !ch) {
    log_message(LOG_ERR, pamh, "pam_get_data() failed");
    return PAM_SESSION_ERR;
  }

  if (!(flags & PAM_SILENT)) {
    display_notice(pamh, 0, 
		   "Remaining one-time passwords: %d of %d%s",
		   ch->remaining, ch->entries,
		   (ch->remaining < ch->entries/2) || (ch->remaining < 20) ?
		   " (time to print new ones with otpw-gen)" : "");
  }

  return PAM_SUCCESS;
}

/* another expected entry point */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, 
				    int argc, const char **argv)
{
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;

  D(log_message(LOG_DEBUG, pamh, "pam_sm_close_session called"));

  /* NOP */

  return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
  MODULE_NAME,
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
