/* libSystem intercept layer that tracks changed files and runs post scripts */

int post_rename(const char *old, const char *new);
int post_unlink(const char *path);
int post_rmdir(const char *path);
