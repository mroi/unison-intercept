#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#pragma clang diagnostic ignored "-Wunused-macros"
#define BUILD \
	CC=${CC:-cc} ; \
	CFLAGS=${CFLAGS:--D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -O3 -fPIC -Wall -Wextra} ; \
	unset PS4; set -x ; \
	$CC -shared $CFLAGS -o libsandbox.so sandbox.c -ldl ; \
	exit

/* sandbox all file manipulations to a subdirectory, optionally read-only */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <dlfcn.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

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

enum sandbox_access { READ, WRITE };
enum sandbox_result { PASS, ABORT };

static const char *const sandbox_access_string[] = { "read", "write" };

static const char *sandbox_prefix;
static size_t sandbox_prefix_length;
static const char *sandbox_exception;
static size_t sandbox_exception_length;
static bool sandbox_writable;


static void __attribute__((constructor)) initialize(void)
{
	sandbox_prefix = getenv("SANDBOX_PREFIX");
	assert(sandbox_prefix);
	sandbox_prefix_length = strlen(sandbox_prefix);

	// allow access to unison archive files, configured with UNISON variable
	sandbox_exception = getenv("UNISON");
	if (sandbox_exception)
		sandbox_exception_length = strlen(sandbox_exception);
	else
		sandbox_exception_length = 0;

	sandbox_writable = !!getenv("SANDBOX_WRITABLE");
}

static enum sandbox_result sandbox_test(const char *path, enum sandbox_access access)
{
	char buffer[PATH_MAX];
	char *resolved = realpath(path, buffer);
	if (!resolved) return ABORT;
	if (sandbox_exception && strncmp(resolved, sandbox_exception, sandbox_exception_length) == 0) return PASS;
	if (access == WRITE && !sandbox_writable) return ABORT;
	if (strncmp(resolved, sandbox_prefix, sandbox_prefix_length) == 0) return PASS;
	return ABORT;
}

/* wrap sandbox_test with a macro to print debug output for sandbox violations */
#define enforce_sandbox(path, access) \
	do { \
		if (sandbox_test(path, access) == ABORT) { \
			fprintf(stderr, "sandbox violation in %s: %s at %s\n", \
				__FUNCTION__, sandbox_access_string[access], path); \
			abort(); \
		} \
	} while (0)

/* functions we want to block completely just print debug output and abort */
#define BLOCK(symbol, return, arguments) \
	return symbol arguments; \
	__attribute__((noreturn)) return symbol arguments \
	{ \
		fprintf(stderr, "sandbox violation: %s called\n", #symbol); \
		abort(); \
	}


/* MARK: - Sandboxed Functions */

int open(const char *path, int flags, ...)
{
	ORIGINAL_SYMBOL(open, (const char *path, int flags, ...))
	int result;

	if (flags & O_WRONLY || flags & O_RDWR || flags & O_CREAT)
		enforce_sandbox(path, WRITE);
	else
		enforce_sandbox(path, READ);

	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT)
		result = original_open(path, flags, va_arg(arg, int));
	else
		result = original_open(path, flags);

	va_end(arg);
	return result;
}


/* MARK: - Blocked Functions */

#define unused __attribute__((__unused__))

/* block dangerous functions */
BLOCK(chroot, int, (unused const char *path))
BLOCK(dlopen, void*, (unused const char *path, unused int mode))
BLOCK(execl, int, (unused const char *path, unused const char *arg, ...))
BLOCK(execle, int, (unused const char *path, unused const char *arg, ...))
BLOCK(execlp, int, (unused const char *file, unused const char *arg, ...))
BLOCK(execv, int, (unused const char *path, unused char *const argv[]))
BLOCK(execve, int, (unused const char *path, unused char *const argv[], unused char *const env[]))
BLOCK(execvex, int, (unused uintptr_t file, unused char *const argv[], unused char *const env[], unused int flags))
BLOCK(execvp, int, (unused const char *file, unused char *const argv[]))
BLOCK(fork, pid_t, (void))
BLOCK(mknod, int, (unused const char *path, unused mode_t mode, unused dev_t dev))
BLOCK(system, int, (unused const char *command))

#ifdef __APPLE__
BLOCK(syscall, int, (unused int number, ...))
#else
BLOCK(syscall, long, (unused long number, ...))
#endif

/* block path-based functions not needed by unison */
typedef struct FTW *ftw_t;
BLOCK(creat, int, (unused const char *path, unused mode_t mode))
BLOCK(fopen, FILE *, (unused const char *path, unused const char *mode))
BLOCK(freopen, FILE *, (unused const char *path, unused const char *mode, unused FILE *file))
BLOCK(ftw, int, (unused const char *path, unused int (*f)(const char *, const struct stat *, int), unused int limit))
BLOCK(ftw64, int, (unused const char *path, unused int (*f)(const char *, const struct stat *, int), unused int limit))
BLOCK(nftw, int, (unused const char *path, unused int (*f)(const char *, const struct stat *, int, ftw_t), unused int limit, unused int flags))
BLOCK(nftw64, int, (unused const char *path, unused int (*f)(const char *, const struct stat *, int, ftw_t), unused int limit, unused int flags))

/* block the ...at versions of path-based functions */
BLOCK(faccessat, int, (unused int fd, unused const char *path, unused int mode, unused int flags))
BLOCK(fchmodat, int, (unused int fd, unused const char *path, unused mode_t mode, unused int flags))
BLOCK(fchownat, int, (unused int fd, unused const char *path, unused uid_t owner, unused gid_t group, unused int flags))
BLOCK(fstatat, int, (unused int fd, unused const char *path, unused struct stat *stat, unused int flags))
BLOCK(futimesat, int, (unused int fd, unused const char *path, unused const struct timeval times[2]))
BLOCK(linkat, int, (unused int fd1, unused const char *path1, unused int fd2, unused const char *path2, unused int flags))
BLOCK(mkdirat, int, (unused int fd, unused const char *path, unused mode_t mode))
BLOCK(mknodat, int, (unused int fd, unused const char *path, unused mode_t mode, unused dev_t dev))
BLOCK(openat, int, (unused int fd, unused const char *path, unused int flags, ...))
BLOCK(readlinkat, ssize_t, (unused int fd, unused const char *path, unused char *buf, unused size_t size))
BLOCK(renameat, int, (unused int fd1, unused const char *old, unused int fd2, unused const char *new))
BLOCK(symlinkat, int, (unused const char *target, unused int fd, unused const char *path))
BLOCK(unlinkat, int, (unused int fd, unused const char *path, unused int flags))
BLOCK(utimensat, int, (unused int fd, unused const char *path, unused const struct timespec times[2], unused int flags))
