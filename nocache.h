/* intercept layer that causes writes to bypass the buffer cache
 *
 * This should improve data safety, because the Unison read check after copying
 * will read back from the physical storage medium, not from the buffer cache.
 * Also, this intercept lowers Unison's scheduler priority to reduce IO impact. */

int nocache_open(const char *path, int flags, ...);
