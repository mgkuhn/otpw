#include <syslog.h>

extern void log_message(int priority, void *pamh,
			const char *format, ...);
#define DEBUG_LOG(...) log_message(LOG_DEBUG, (void *) 0, __VA_ARGS__)
#include "otpw.c"
