/* intercept layer that presents unison with encrypted file content */

struct stat;

[[nodiscard]] int encrypt_open(const char *path, int flags, ...);
[[nodiscard]] int encrypt_close(int fd);
[[nodiscard]] ssize_t encrypt_read(int fd, void *buf, size_t bytes);
[[nodiscard]] ssize_t encrypt_write(int fd, const void *buf, size_t bytes);
[[nodiscard]] int encrypt_stat(const char * restrict path, struct stat * restrict buf);
[[nodiscard]] int encrypt_lstat(const char * restrict path, struct stat * restrict buf);
#ifdef __APPLE__
[[nodiscard]] int encrypt_getattrlist(const char *path, void *attrs, void *buf, size_t buf_size, unsigned int options);
#endif

void encrypt_reset(void);
