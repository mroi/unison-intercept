#include <stdarg.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "nocache.h"


static void __attribute__((constructor)) initialize(void)
{
	// lower Unison's priority to avoid disk hogging
	setpriority(PRIO_PROCESS, 0, 10);
}


/* MARK: - Intercepted Functions */

int nocache_open(const char *path, int flags, ...)
{
	int result;
	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT) {
		mode_t mode = va_arg(arg, int);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);
	}

	if (result > 0 &&
		((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR))
		fcntl(result, F_NOCACHE, 1);

	va_end(arg);
	return result;
}
