/* Stacked libSystem intercept.
 *
 * All libSystem functions can be replaced with a new implementation. A per-thread
 * context identifier allows calling the intercepted libSystem functions without
 * running into an endless recursion. Instead, the next layer of intercepts will
 * be called, with the lowest layer being the original libSystem code.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>

#include <SystemConfiguration/SystemConfiguration.h>

#include "nocache.h"
#include "config.h"
#include "post.h"

#include <fcntl.h>
#include <asl.h>

#define ORIGINAL_SYMBOL(symbol, arguments) \
	static int (*original_##symbol)arguments; \
	if (!original_##symbol) { \
		original_##symbol = (int (*)arguments)dlsym(RTLD_NEXT, #symbol); \
		if (!original_##symbol) { \
			fprintf(stderr, "original symbol `" #symbol "` not found by dlsym()\n"); \
			abort(); \
		} \
	}

static pthread_key_t context;

/* The intercept layers in use.
 * Thread-local storage remembers which one has been called. */
enum intercept_id {
	NONE = 0,
	NOCACHE,   // disable caching of file writes
	CONFIG,    // process our own entries in Unison config files
	POST,      // execute post scripts when files change
	ORIGINAL
};

#define PROLOGUE \
	enum intercept_id current_context = (enum intercept_id)(void *)pthread_getspecific(context)

static inline void CONTEXT(enum intercept_id id)
{
	pthread_setspecific(context, (void *)id);
}

#define EPILOGUE \
	pthread_setspecific(context, (void *)current_context)


static void __attribute__((constructor)) initialize(void)
{
	if (pthread_key_create(&context, NULL) != 0) {
		fputs("per-thread calling context could not be initialized\n", stderr);
		abort();
	}

	// set UNISONLOCALHOSTNAME to the local hostname
	CFStringRef nameString = SCDynamicStoreCopyLocalHostName(NULL);
	if (nameString) {
		CFIndex size = CFStringGetLength(nameString) + sizeof(".local");
		char *name = malloc(size);
		if (CFStringGetCString(nameString, name, size, kCFStringEncodingASCII)) {
			name = strcat(name, ".local");
			setenv("UNISONLOCALHOSTNAME", name, 1);
		}
		free(name);
		CFRelease(nameString);
	}
}


/* MARK: - Intercepted Functions */

int open(const char *path, int flags, ...)
{
	ORIGINAL_SYMBOL(open, (const char *path, int flags, ...));
	int result;
	PROLOGUE;

	va_list arg;
	va_start(arg, flags);
	switch (current_context) {
		case NONE:
			CONTEXT(NOCACHE);
			if (flags & O_CREAT)
				result = nocache_open(path, flags, va_arg(arg, int));
			else
				result = nocache_open(path, flags);
			break;
		case NOCACHE:
			CONTEXT(CONFIG);
			if (flags & O_CREAT)
				result = config_open(path, flags, va_arg(arg, int));
			else
				result = config_open(path, flags);
			break;
		case CONFIG:
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			if (flags & O_CREAT)
				result = original_open(path, flags, va_arg(arg, int));
			else
				result = original_open(path, flags);
			break;
	}
	va_end(arg);

	EPILOGUE;
	return result;
}

int close(int fd)
{
	ORIGINAL_SYMBOL(close, (int fd));
	int result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
			CONTEXT(CONFIG);
			result = config_close(fd);
			break;
		case CONFIG:
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_close(fd);
			break;
	}

	EPILOGUE;
	return result;
}

ssize_t read(int fd, void *buf, size_t bytes)
{
	ORIGINAL_SYMBOL(read, (int fd, void *buf, size_t bytes));
	ssize_t result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
			CONTEXT(CONFIG);
			result = config_read(fd, buf, bytes);
			break;
		case CONFIG:
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_read(fd, buf, bytes);
			break;
	}

	EPILOGUE;
	return result;
}

int rename(const char *old, const char *new)
{
	ORIGINAL_SYMBOL(rename, (const char *old, const char *new));
	int result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			CONTEXT(POST);
			result = post_rename(old, new);
			break;
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_rename(old, new);
			break;
	}

	EPILOGUE;
	return result;
}

int unlink(const char *path)
{
	ORIGINAL_SYMBOL(unlink, (const char *path));
	int result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			CONTEXT(POST);
			result = post_unlink(path);
			break;
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_unlink(path);
			break;
	}

	EPILOGUE;
	return result;
}

int rmdir(const char *path)
{
	ORIGINAL_SYMBOL(rmdir, (const char *path));
	int result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			CONTEXT(POST);
			result = post_rmdir(path);
			break;
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_rmdir(path);
			break;
	}

	EPILOGUE;
	return result;
}

int asl_send(aslclient ac, aslmsg msg)
{
	ORIGINAL_SYMBOL(asl_send, (aslclient ac, aslmsg msg));
	int result;
	PROLOGUE;

	switch (current_context) {
		case NONE:
		case NOCACHE:
			CONTEXT(CONFIG);
			result = config_asl_send(ac, msg);
			break;
		case CONFIG:
		case POST:
			CONTEXT(ORIGINAL);
		case ORIGINAL:
			result = original_asl_send(ac, msg);
			break;
	}

	EPILOGUE;
	return result;
}
