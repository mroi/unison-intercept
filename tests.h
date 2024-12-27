#include <fcntl.h>
#include "config.h"

/* Explain to Swift concurrency checking that this shared state is OK. */
extern struct config_s config __attribute__((swift_attr("nonisolated(unsafe)")));

/* Because open() is variadic in C, it is imported differently into Swift,
 * causing the intercept to not function properly. Instead, we provide non-
 * variadic wrappers for open. */
int open2(const char *path, int flags) __attribute__((nonnull(1),swift_name("interceptOpen(_:_:)")));
int open3(const char *path, int flags, mode_t mode) __attribute__((nonnull(1),swift_name("interceptOpen(_:_:_:)")));

int open2(const char *path, int flags)
{
	return open(path, flags);
}

int open3(const char *path, int flags, mode_t mode)
{
	return open(path, flags, mode);
}
