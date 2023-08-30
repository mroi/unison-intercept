/* intercept layer that presents unison with encrypted file content */

struct stat;

int encrypt_open(const char *path, int flags, ...);
int encrypt_close(int fd);
int encrypt_stat(const char * restrict path, struct stat * restrict buf);
int encrypt_lstat(const char * restrict path, struct stat * restrict buf);

void encrypt_reset(void);
