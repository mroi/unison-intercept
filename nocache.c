#include <stdarg.h>
#include <stdbool.h>
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
	bool writable = (flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR;

	int result;
	va_list arg;
	va_start(arg, flags);

#ifndef __APPLE__
	if (writable) flags |= O_DIRECT;
#endif

	if (flags & O_CREAT) {
		mode_t mode = (mode_t)va_arg(arg, unsigned);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);
	}

#ifdef __APPLE__
	if (result > 0 && writable) fcntl(result, F_NOCACHE, 1);
#endif

	va_end(arg);
	return result;
}
