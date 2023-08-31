#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

#include "config.h"
#include "umask.h"


static mode_t mode_restrict(const char *path, mode_t mode);


/* MARK: - Intercepted Functions */

int umask_open(const char *path, int flags, ...)
{
	int result;
	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT) {
		mode_t mode = (mode_t)va_arg(arg, unsigned);
		mode = mode_restrict(path, mode);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);
	}

	va_end(arg);
	return result;
}

int umask_mkdir(const char *path, mode_t mode)
{
	mode = mode_restrict(path, mode);
	return mkdir(path, mode);
}

int umask_symlink(const char *target, const char *path)
{
	mode_t current = umask(S_IWGRP | S_IWOTH);
	mode_t restricted_mode = mode_restrict(path, (S_IRWXU | S_IRWXG | S_IRWXO) & ~current);
	mode_t restricted_mask = (S_IRWXU | S_IRWXG | S_IRWXO) & ~restricted_mode;
	(void)umask(restricted_mask);
	int result = symlink(target, path);
	(void)umask(current);
	return result;
}


/* MARK: - Helper Functions */

static mode_t mode_restrict(const char *path, mode_t mode)
{
	static struct string_s home = { .string = NULL, .length = 0 };
	if (!home.string) {
		char *home_env = getenv("HOME");
		assert(home_env);
		home.length = strlen(home_env) + sizeof((char)'/');
		home.string = malloc(home.length + sizeof((char)'\0'));
		if (!home.string) abort();
		snprintf(home.string, home.length + sizeof((char)'\0'), "%s/", home_env);
	}

	bool is_below_home = strncmp(path, home.string, home.length) == 0;
	bool is_in_home = is_below_home && strchr(path + home.length, '/') == NULL;
	if (is_in_home) mode = mode & S_IRWXU;  // remove group and other permissions

	return mode;
}
