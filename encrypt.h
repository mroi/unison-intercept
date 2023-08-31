/* intercept layer that presents unison with encrypted file content */

struct stat;

int encrypt_open(const char *path, int flags, ...);
int encrypt_close(int fd);
ssize_t encrypt_read(int fd, void *buf, size_t bytes);
ssize_t encrypt_write(int fd, const void *buf, size_t bytes);
int encrypt_stat(const char * restrict path, struct stat * restrict buf);
int encrypt_lstat(const char * restrict path, struct stat * restrict buf);

void encrypt_reset(void);
