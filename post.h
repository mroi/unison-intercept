/* libSystem intercept layer that tracks changed files and runs post scripts */

struct stat;

int post_open(const char *path, int flags, ...);
int post_stat(const char * restrict path, struct stat * restrict buf);
int post_lstat(const char * restrict path, struct stat * restrict buf);
int post_rename(const char *old, const char *new);
int post_unlink(const char *path);
int post_rmdir(const char *path);

void post_reset(void);
