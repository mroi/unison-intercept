/* intercept layer that tracks changed files and runs pre and post scripts */

struct stat;

[[nodiscard]] int prepost_open(const char *path, int flags, ...);
[[nodiscard]] int prepost_stat(const char * restrict path, struct stat * restrict buf);
[[nodiscard]] int prepost_lstat(const char * restrict path, struct stat * restrict buf);
[[nodiscard]] int prepost_rename(const char *old, const char *new);
[[nodiscard]] int prepost_unlink(const char *path);
[[nodiscard]] int prepost_rmdir(const char *path);

void prepost_reset(void);
