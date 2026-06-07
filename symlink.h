/* intercept layer that creates symlinks before directories are traversed */

#include <dirent.h>

struct stat;

[[nodiscard]] int symlink_stat(const char * restrict path, struct stat * restrict buf);
[[nodiscard]] int symlink_lstat(const char * restrict path, struct stat * restrict buf);
[[nodiscard]] DIR *symlink_opendir(const char *path);
[[nodiscard]] int symlink_closedir(DIR *dir);

void symlink_reset(void);
