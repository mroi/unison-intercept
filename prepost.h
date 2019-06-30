/* intercept layer that tracks changed files and runs pre and post scripts */

struct stat;

int prepost_open(const char *path, int flags, ...);
int prepost_stat(const char * restrict path, struct stat * restrict buf);
int prepost_lstat(const char * restrict path, struct stat * restrict buf);
int prepost_rename(const char *old, const char *new);
int prepost_unlink(const char *path);
int prepost_rmdir(const char *path);

void prepost_reset(void);
