/*
 * One-time password login capability - configuration options
 *
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/>
 */

#ifndef OTPW_CONF_H
#define OTPW_CONF_H

/*
 * List of shell commands that produce high entropy output.
 * The output of all these commands will be hashed together with
 * timing information to seed the random number generator
 */

#define ENTROPY_CMDS \
"head -c 20 /dev/urandom 2>&1", \
"ls -lu /etc/. /tmp/. / /usr/. /bin/. /usr/bin/.", \
"PATH=/usr/ucb:/bin:/usr/bin;ps lax", \
"last | head -50", \
"uptime;netstat -n;hostname;date;w", \
"cd $HOME; cat .pgp/randseed.bin .ssh/random_seed .otpw 2>&1"
/* too slow: "PATH=/usr/bin/X11/;xwd -root -silent 2>&1||xwd -root 2>&1" */

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
 * Number of concatenated passwords requested while another one is locked.
 * A reasonable value is 3.
 */

#define OTPW_MULTI 3

/*
 * Stored hash is OTPW_HLEN characters or OTPW_HLEN*6 bits long.
 * A reasonable value is 12 (72 bits).
 */

#define OTPW_HLEN 12

/*
 * Characteristic first line that allows recognition of an OTPW file
 */

#define OTPW_MAGIC "OTPW1\n"

/*
 * Minimum password entropy [bits] permitted by otpw-gen (option -e)
 */

#define EMIN 30

#endif
