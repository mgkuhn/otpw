/*
 * One-time password login capability - configuration options
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 *
 * $Id: conf.h,v 1.2 2003-06-16 16:25:06 mgk25 Exp $
 */

#ifndef OTPW_CONF_H
#define OTPW_CONF_H

/*
 * List of shell commands that produce high entropy output.
 * The output of all these commands will be hashed together with
 * timing information to seed the random number generator
 */

#define ENTROPY_CMDS \
"head -c 20 /dev/random 2>&1", \
"ls -lu /etc/. /tmp/. / /usr/. /bin/. /usr/bin/.", \
"PATH=/usr/ucb:/bin:/usr/bin;ps lax", \
"last | head -50", \
"uptime;netstat -n;hostname;date;w", \
"cd $HOME; cat .pgp/randseed.bin .ssh/random_seed .otpw 2>&1", \
"PATH=/usr/bin/X11/;xwd -root -silent 2>&1||xwd -root 2>&1"

/*
 * Environment variable settings for the entropy generating
 * shell commands
 */

#define ENTROPY_ENV \
"PATH=/bin:/usr/bin:/sbin:/usr/sbin:/etc:/usr/etc:/usr/ucb"

/*
 * Path for the one-time password file. Pathnames not starting with
 * a slash will be relative to the user's home directory.
 */

#define OTPW_FILE ".otpw"

/*
 * Path for the temporary version of OTPW_FILE (needed for atomicity)
 */

#define OTPW_TMP ".otpw.tmp"

/*
 * Path for the one-time password lock symlink.
 */

#define OTPW_LOCK ".otpw.lock"

/*
 * One-time password is OTPW_GROUPS*4 characters or OTPW_GROUPS*24 bits long.
 * Reasonable values are 2 (48-bit security) or 3 (72-bit high security).
 */

#define OTPW_GROUPS 3

/*
 * Number of concatenated passwords requested while another one is locked.
 * A reasonable value is 3.
 */

#define OTPW_MULTI 3

/*
 * Characteristic first line that allows recognicion of an OTPW file
 */

#define OTPW_MAGIC "OTPW 1.0\n"

#endif
