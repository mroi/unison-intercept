#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>

#include "config.h"
#include "encrypt.h"
#include "mbedtls/gcm.h"


// we add this to the beginning of files
struct file_header_s {
	unsigned char iv[128 / CHAR_BIT];
	size_t trailer_start;
};

// we add this to the end of files
struct file_trailer_s {
	unsigned char auth_tag[128 / CHAR_BIT];
};

static pthread_mutex_t filemap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct filemap_s {
	char *path;
	int fd;
	unsigned char key[256 / CHAR_BIT];
	struct filemap_s *next;
} *filemap = NULL;

static bool encrypt_search_key(const char *path, unsigned char key_out[256 / CHAR_BIT]);
static struct filemap_s *file_from_path(const char *path);
static struct filemap_s *file_from_fd(int fd);


static void __attribute__((constructor)) initialize(void)
{
	// test crypto functionality
	assert(mbedtls_gcm_self_test(0) == 0);
}


/* MARK: - Intercepted Functions */

int encrypt_open(const char *path, int flags, ...)
{
	int result;
	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT) {
		mode_t mode = (mode_t)va_arg(arg, unsigned);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);
	}

	unsigned char key[256 / CHAR_BIT];
	if (encrypt_search_key(path, key)) {
		pthread_mutex_lock(&filemap_lock);
		struct filemap_s *file = file_from_path(path);

		if (!file) {
			file = malloc(sizeof(struct filemap_s));
			file->path = strdup(path);
			memcpy(file->key, key, sizeof(file->key));
			file->next = filemap;
			filemap = file;
		}

		file->fd = result;

		pthread_mutex_unlock(&filemap_lock);
	}

	va_end(arg);
	return result;
}

int encrypt_close(int fd)
{
	int result = close(fd);

	pthread_mutex_lock(&filemap_lock);
	struct filemap_s *file = file_from_fd(fd);
	if (file) {
		file->fd = -1;
	}
	pthread_mutex_unlock(&filemap_lock);

	return result;
}

int encrypt_stat(const char * restrict path, struct stat * restrict buf)
{
	int result = stat(path, buf);

	if ((buf->st_mode & S_IFREG) && encrypt_search_key(path, NULL)) {
		// we will encrypt on read, so increase reported size by encryption header and trailer
		buf->st_size += sizeof(struct file_header_s) + sizeof(struct file_trailer_s);
	}

	return result;
}

int encrypt_lstat(const char * restrict path, struct stat * restrict buf)
{
	int result = lstat(path, buf);

	if ((buf->st_mode & S_IFREG) && encrypt_search_key(path, NULL)) {
		// we will encrypt on read, so increase reported size by encryption header and trailer
		buf->st_size += sizeof(struct file_header_s) + sizeof(struct file_trailer_s);
	}

	return result;
}


/* MARK: - Helper Functions */

static bool encrypt_search_key(const char *path, unsigned char key_out[256 / CHAR_BIT])
{
	bool found = false;

	pthread_mutex_lock(&config.lock);
	for (struct encrypt_s *encrypt = config.encrypt; encrypt; encrypt = encrypt->next) {
		if (config.root[0].string) {
			size_t size = config.root[0].length + sizeof("/") + encrypt->path.length;
			buffer_alloc(&config.scratchpad, size);
			snprintf(config.scratchpad.buffer, config.scratchpad.size, "%s/%s", config.root[0].string, encrypt->path.string);
			if (fnmatch(config.scratchpad.buffer, path, FNM_PATHNAME | FNM_LEADING_DIR) == 0) {
				if (key_out) memcpy(key_out, encrypt->key, sizeof(encrypt->key));
				found = true;
				break;
			}
		}
	}
	pthread_mutex_unlock(&config.lock);

	return found;
}

static struct filemap_s *file_from_path(const char *path)
{
	struct filemap_s *file;
	for (file = filemap; file; file = file->next) {
		if (strcmp(file->path, path) == 0) break;
	}
	return file;
}

static struct filemap_s *file_from_fd(int fd)
{
	struct filemap_s *file;
	for (file = filemap; file; file = file->next) {
		if (file->fd == fd) break;
	}
	return file;
}

void encrypt_reset(void)
{
	pthread_mutex_lock(&filemap_lock);

	struct filemap_s *next;
	for (struct filemap_s *file = filemap; file; file = next) {
		next = file->next;
		free(file->path);
		free(file);
	}
	filemap = NULL;

	pthread_mutex_unlock(&filemap_lock);
}
