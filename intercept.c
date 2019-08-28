/* stacked libSystem/libc intercept
 *
 * All libSystem/libc functions can be replaced with a new implementation. A
 * per-thread context identifier allows calling the intercepted libSystem/libc
 * functions without running into an endless recursion. Instead, the next layer
 * of intercepts will be called, with the lowest layer being the original
 * libSystem/libc code.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <dlfcn.h>

#ifdef __APPLE__
#define OBJC_OLD_DISPATCH_PROTOTYPES 1
#include <string.h>
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFString.h>
#include <SystemConfiguration/SCDynamicStoreCopySpecific.h>
#include <objc/objc.h>
#include <objc/runtime.h>
#endif

#include "nocache.h"
#include "config.h"
#include "prepost.h"
#include "symlink.h"
#include "umask.h"

#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#define ORIGINAL_SYMBOL(symbol, arguments) \
	static int (*original_##symbol)arguments; \
	local: if (!original_##symbol) { \
		Dl_info info; \
		/* retrieve internal symbol name of current function
		 * We cannot use the symbol argument directly, because it may be altered
		 * by defines in headers like ‘open’ to ‘open64’. We also cannot use a
		 * pointer to the current function with dladdr(), because it points into
		 * a dynamic linking table on some architectures (Solaris) and thus dladdr()
		 * yields no useful symbol name. Our only chance is a pointer to a local
		 * label, which is a GNU extension, but apparently the only portable way. */ \
		int result = dladdr(&&local, &info); \
		assert(result && info.dli_sname); \
		original_##symbol = (int (*)arguments)dlsym(RTLD_NEXT, info.dli_sname); \
		assert(original_##symbol); \
	}

/* The intercept layers in use.
 * Thread-local storage remembers which one has been called. */
enum intercept_id {
	NONE,
	NOCACHE,   // disable caching of file writes
	CONFIG,    // process our own entries in Unison config files
	PREPOST,   // execute post scripts when files change
	SYMLINK,   // create symlinks before traversing directories
	UMASK,     // restricts umask in home directory
	ORIGINAL
};

static _Thread_local enum intercept_id context = NONE;


#ifdef __APPLE__

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
	prepost_reset();
	symlink_reset();
	return previous_implementation(self, command, arg1);
}

#endif


/* MARK: - Intercepted Functions */

int open(const char *path, int flags, ...)
{
	ORIGINAL_SYMBOL(open, (const char *path, int flags, ...))
	int result;
	enum intercept_id saved_context = context;

	va_list arg;
	va_start(arg, flags);
	switch (context) {
	case NONE:
		context = NOCACHE;
		if (flags & O_CREAT)
			result = nocache_open(path, flags, va_arg(arg, unsigned));
		else
			result = nocache_open(path, flags);
		break;
	case NOCACHE:
		context = CONFIG;
		if (flags & O_CREAT)
			result = config_open(path, flags, va_arg(arg, unsigned));
		else
			result = config_open(path, flags);
		break;
	case CONFIG:
		context = PREPOST;
		if (flags & O_CREAT)
			result = prepost_open(path, flags, va_arg(arg, unsigned));
		else
			result = prepost_open(path, flags);
		break;
	case PREPOST:
	case SYMLINK:
		context = UMASK;
		if (flags & O_CREAT)
			result = umask_open(path, flags, va_arg(arg, unsigned));
		else
			result = umask_open(path, flags);
		break;
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		if (flags & O_CREAT)
			result = original_open(path, flags, va_arg(arg, unsigned));
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
	ORIGINAL_SYMBOL(close, (int fd))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
		context = CONFIG;
		result = config_close(fd);
		break;
	case CONFIG:
	case PREPOST:
	case SYMLINK:
	case UMASK:
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
	ORIGINAL_SYMBOL(read, (int fd, void *buf, size_t bytes))
	ssize_t result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
		context = CONFIG;
		result = config_read(fd, buf, bytes);
		break;
	case CONFIG:
	case PREPOST:
	case SYMLINK:
	case UMASK:
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
	ORIGINAL_SYMBOL(stat, (const char * restrict path, struct stat * restrict buf))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
		context = PREPOST;
		result = prepost_stat(path, buf);
		break;
	case PREPOST:
		context = SYMLINK;
		result = symlink_stat(path, buf);
		break;
	case SYMLINK:
	case UMASK:
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
	ORIGINAL_SYMBOL(lstat, (const char * restrict path, struct stat * restrict buf))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
		context = PREPOST;
		result = prepost_lstat(path, buf);
		break;
	case PREPOST:
		context = SYMLINK;
		result = symlink_lstat(path, buf);
		break;
	case SYMLINK:
	case UMASK:
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
	ORIGINAL_SYMBOL(rename, (const char *old, const char *new))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
		context = PREPOST;
		result = prepost_rename(old, new);
		break;
	case PREPOST:
	case SYMLINK:
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_rename(old, new);
		break;
	}

	context = saved_context;
	return result;
}

int symlink(const char *target, const char *path)
{
	ORIGINAL_SYMBOL(symlink, (const char *target, const char *path))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
	case PREPOST:
	case SYMLINK:
		context = UMASK;
		result = umask_symlink(target, path);
		break;
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_symlink(target, path);
		break;
	}

	context = saved_context;
	return result;
}

int unlink(const char *path)
{
	ORIGINAL_SYMBOL(unlink, (const char *path))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
		context = PREPOST;
		result = prepost_unlink(path);
		break;
	case PREPOST:
	case SYMLINK:
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_unlink(path);
		break;
	}

	context = saved_context;
	return result;
}

DIR *opendir(const char *path)
{
	ORIGINAL_SYMBOL(opendir, (const char *path))
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
	DIR *(*typecorrect_original_opendir)(const char *path) = original_opendir;
#pragma clang diagnostic pop
	DIR *result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
	case PREPOST:
		context = SYMLINK;
		result = symlink_opendir(path);
		break;
	case SYMLINK:
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = typecorrect_original_opendir(path);
		break;
	}

	context = saved_context;
	return result;
}

int closedir(DIR *dir)
{
	ORIGINAL_SYMBOL(closedir, (DIR *dir))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
	case PREPOST:
		context = SYMLINK;
		result = symlink_closedir(dir);
		break;
	case SYMLINK:
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_closedir(dir);
		break;
	}

	context = saved_context;
	return result;
}

int mkdir(const char *path, mode_t mode)
{
	ORIGINAL_SYMBOL(mkdir, (const char *path, mode_t mode))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
	case PREPOST:
	case SYMLINK:
		context = UMASK;
		result = umask_mkdir(path, mode);
		break;
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_mkdir(path, mode);
		break;
	}

	context = saved_context;
	return result;
}

int rmdir(const char *path)
{
	ORIGINAL_SYMBOL(rmdir, (const char *path))
	int result;
	enum intercept_id saved_context = context;

	switch (context) {
	case NONE:
	case NOCACHE:
	case CONFIG:
		context = PREPOST;
		result = prepost_rmdir(path);
		break;
	case PREPOST:
	case SYMLINK:
	case UMASK:
		context = ORIGINAL;
	case ORIGINAL:
		result = original_rmdir(path);
		break;
	}

	context = saved_context;
	return result;
}
