/* intercept layer that creates symlinks before directories are traversed */

#include <dirent.h>

struct stat;

int symlink_stat(const char * restrict path, struct stat * restrict buf);
int symlink_lstat(const char * restrict path, struct stat * restrict buf);
DIR *symlink_opendir(const char *path);
int symlink_closedir(DIR *dir);

void symlink_reset(void);
