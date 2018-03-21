/* Stacked libSystem intercept.
 *
 * All libSystem functions can be replaced with a new implementation. A per-thread
 * context identifier allows calling the intercepted libSystem functions without
 * running into an endless recursion. Instead, the next layer of intercepts will
 * be called, with the lowest layer being the original libSystem code.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <dlfcn.h>

#include <SystemConfiguration/SystemConfiguration.h>
#include <objc/runtime.h>

#include "nocache.h"
#include "config.h"
#include "post.h"

#include <fcntl.h>
#include <sys/stat.h>

#define ORIGINAL_SYMBOL(symbol, arguments) \
	static int (*original_##symbol)arguments; \
	if (!original_##symbol) { \
		Dl_info info; \
		/* retrieve internal symbol name of current function */ \
		int result = dladdr((void *)symbol, &info); \
		assert(result && info.dli_sname); \
		original_##symbol = (int (*)arguments)dlsym(RTLD_NEXT, info.dli_sname); \
		assert(original_##symbol); \
	}

/* The intercept layers in use.
 * Thread-local storage remembers which one has been called. */
enum intercept_id {
	NONE = 0,
	NOCACHE,   // disable caching of file writes
	CONFIG,    // process our own entries in Unison config files
	POST,      // execute post scripts when files change
	ORIGINAL
};

static _Thread_local enum intercept_id context = NONE;

/* Objective-C method swizzling to intercept connections to a new profile */
static IMP previous_implementation;
static void *profile_intercept(id self, SEL command, void *arg1);


static void __attribute__((constructor)) initialize(void)
{
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
	
	// Objective-C method swizzling
	Class class = objc_getRequiredClass("MyController");
	SEL selector = sel_registerName("connect:");
	assert(class && selector);
	Method method = class_getInstanceMethod(class, selector);
	assert(method);
	previous_implementation = method_setImplementation(method, (IMP)profile_intercept);
	assert(previous_implementation);
}

static void *profile_intercept(id self, SEL command, void *arg1)
{
	// the user changed to a different Unison profile, call reset functions
	config_reset();
	post_reset();
	previous_implementation(self, command, arg1);
}


/* MARK: - Intercepted Functions */

int open(const char *path, int flags, ...)
{
	ORIGINAL_SYMBOL(open, (const char *path, int flags, ...));
	int result;
	enum intercept_id saved_context = context;

	va_list arg;
	va_start(arg, flags);
	switch (context) {
		case NONE:
			context = NOCACHE;
			if (flags & O_CREAT)
				result = nocache_open(path, flags, va_arg(arg, int));
			else
				result = nocache_open(path, flags);
			break;
		case NOCACHE:
			context = CONFIG;
			if (flags & O_CREAT)
				result = config_open(path, flags, va_arg(arg, int));
			else
				result = config_open(path, flags);
			break;
		case CONFIG:
			context = POST;
			if (flags & O_CREAT)
				result = post_open(path, flags, va_arg(arg, int));
			else
				result = post_open(path, flags);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			if (flags & O_CREAT)
				result = original_open(path, flags, va_arg(arg, int));
			else
				result = original_open(path, flags);
			break;
	}
	va_end(arg);

	context = saved_context;
	return result;
}

int close(int fd)
{
	ORIGINAL_SYMBOL(close, (int fd));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
			context = CONFIG;
			result = config_close(fd);
			break;
		case CONFIG:
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_close(fd);
			break;
	}

	context = saved_context;
	return result;
}

ssize_t read(int fd, void *buf, size_t bytes)
{
	ORIGINAL_SYMBOL(read, (int fd, void *buf, size_t bytes));
	ssize_t result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
			context = CONFIG;
			result = config_read(fd, buf, bytes);
			break;
		case CONFIG:
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_read(fd, buf, bytes);
			break;
	}

	context = saved_context;
	return result;
}

int stat(const char * restrict path, struct stat * restrict buf)
{
	ORIGINAL_SYMBOL(stat, (const char * restrict path, struct stat * restrict buf));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			context = POST;
			result = post_stat(path, buf);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_stat(path, buf);
			break;
	}

	context = saved_context;
	return result;
}

int lstat(const char * restrict path, struct stat * restrict buf)
{
	ORIGINAL_SYMBOL(lstat, (const char * restrict path, struct stat * restrict buf));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			context = POST;
			result = post_lstat(path, buf);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_lstat(path, buf);
			break;
	}

	context = saved_context;
	return result;
}

int rename(const char *old, const char *new)
{
	ORIGINAL_SYMBOL(rename, (const char *old, const char *new));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			context = POST;
			result = post_rename(old, new);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_rename(old, new);
			break;
	}

	context = saved_context;
	return result;
}

int unlink(const char *path)
{
	ORIGINAL_SYMBOL(unlink, (const char *path));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			context = POST;
			result = post_unlink(path);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_unlink(path);
			break;
	}

	context = saved_context;
	return result;
}

int rmdir(const char *path)
{
	ORIGINAL_SYMBOL(rmdir, (const char *path));
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
		case NONE:
		case NOCACHE:
		case CONFIG:
			context = POST;
			result = post_rmdir(path);
			break;
		case POST:
			context = ORIGINAL;
		case ORIGINAL:
			result = original_rmdir(path);
			break;
	}

	context = saved_context;
	return result;
}
