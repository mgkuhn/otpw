/*
 * One-time password login capability
 *
 * This file is just a variant of otpw.c, in which the debugging
 * messages are directed to the log_message function of pam_otpw.c
 * instead of to stderr. Link otpw-l.o instead of otpw.o into
 * pam_otpw.so for debugging purposes.
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: otpw-l.c,v 1.4 2003-06-24 20:43:29 mgk25 Exp $
 */


#include <syslog.h>


#ifndef DEBUG_LOG
#  if DEBUG
extern void log_message(int priority, void *pamh,
			const char *format, ...);
#    define DEBUG_LOG(...) if (ch->flags & OTPW_DEBUG) \
                             log_message(LOG_DEBUG, (void *) 0, __VA_ARGS__)
#  endif
#endif

#include "otpw.c"
