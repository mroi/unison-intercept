/* intercept layer that restricts the umask for files in the home directory */

#include <sys/types.h>

[[nodiscard]] int umask_open(const char *path, int flags, ...);
[[nodiscard]] int umask_mkdir(const char *path, mode_t mode);
[[nodiscard]] int umask_symlink(const char *target, const char *path);
