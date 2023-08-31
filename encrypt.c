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
#include <errno.h>
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
	enum { READ, WRITE, CLOSE } state;
	size_t position;
	mbedtls_gcm_context gcm;
	struct file_header_s header;
	struct buffer_s content_buffer;
	struct file_trailer_s trailer;
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
			file->header.trailer_start = 0;
			file->content_buffer.size = 0;
			file->content_buffer.buffer = NULL;
			file->next = filemap;
			filemap = file;
		} else {
			assert(file->state == CLOSE);
		}

		switch (flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
		case O_RDONLY:
			file->state = READ;
			break;
		case O_WRONLY:
			file->state = WRITE;
			break;
		default:
			abort();
		}
		file->fd = result;
		file->position = 0;

		mbedtls_gcm_init(&file->gcm);
		int gcm_result = mbedtls_gcm_setkey(&file->gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
		assert(gcm_result == 0);

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
		file->state = CLOSE;
		file->position = 0;
		mbedtls_gcm_free(&file->gcm);
	}
	pthread_mutex_unlock(&filemap_lock);

	return result;
}

ssize_t encrypt_read(int fd, void *buf, size_t bytes)
{
	ssize_t result = 0;

	pthread_mutex_lock(&filemap_lock);
	struct filemap_s *file = file_from_fd(fd);

	if (file) {
		assert(file->state == READ);
		unsigned char *target = buf;

		if (bytes > 0 && file->position == 0 && file->header.trailer_start == 0) {
			// initialize the file header
			arc4random_buf(file->header.iv, sizeof(file->header.iv));
			struct stat stat_buf;
			int stat_result = fstat(file->fd, &stat_buf);
			assert(stat_result == 0);
			file->header.trailer_start = sizeof(struct file_header_s) + (size_t)stat_buf.st_size;
		}

		if (bytes > 0 && file->position < sizeof(struct file_header_s)) {
			// first emit the header to the caller
			size_t to_emit = sizeof(struct file_header_s) - file->position;
			if (to_emit > bytes) to_emit = bytes;
			const char *source = (const char *)&file->header + file->position;
			memcpy(target, source, to_emit);
			target += to_emit;
			result += to_emit;
			bytes -= to_emit;
			file->position += to_emit;
		}

		if (bytes > 0 && file->position == sizeof(struct file_header_s)) {
			// start the crypto context
			int gcm_result = mbedtls_gcm_starts(&file->gcm, MBEDTLS_GCM_ENCRYPT, file->header.iv, sizeof(file->header.iv));
			assert(gcm_result == 0);
		}

		if (bytes > 0 && file->position < file->header.trailer_start) {
			// emit encrypted file content to the caller
			size_t to_emit = file->header.trailer_start - file->position;
			if (to_emit > bytes) to_emit = bytes;
			buffer_alloc(&file->content_buffer, to_emit);

			// read file data
			size_t to_read = to_emit;
			char *buffer = file->content_buffer.buffer;
			while (to_read > 0) {
				ssize_t read_result = read(fd, buffer, to_read);
				if (read_result < 0 && errno == EINTR) continue;
				if (read_result < 0) return read_result;
				if (read_result == 0) break;
				buffer += read_result;
				to_read -= (size_t)read_result;
			}
			to_emit -= to_read;

			// perform encryption
			const unsigned char *source = (const unsigned char *)file->content_buffer.buffer;
			size_t gcm_size;
			int gcm_result = mbedtls_gcm_update(&file->gcm, source, to_emit, target, bytes, &gcm_size);
			assert(gcm_result == 0);

			target += gcm_size;
			result += gcm_size;
			bytes -= gcm_size;
			file->position += to_emit;
		}

		if (bytes > 0 && file->position == file->header.trailer_start) {
			// generate authentication tag
			size_t gcm_size;
			int gcm_result = mbedtls_gcm_finish(&file->gcm, target, bytes, &gcm_size, file->trailer.auth_tag, sizeof(file->trailer.auth_tag));
			assert(gcm_result == 0);
			target += gcm_size;
			result += gcm_size;
			bytes -= gcm_size;
		}

		if (bytes > 0 && file->position >= file->header.trailer_start) {
			// lastly emit the file trailer to the caller
			size_t to_emit = sizeof(struct file_trailer_s);
			to_emit -= file->position - file->header.trailer_start;
			if (to_emit > bytes) to_emit = bytes;
			const char *source = (const char *)&file->trailer;
			source += file->position - file->header.trailer_start;
			memcpy(target, source, to_emit);
			result += to_emit;
			file->position += to_emit;
		}

	} else {
		result = read(fd, buf, bytes);
	}

	pthread_mutex_unlock(&filemap_lock);
	return result;
}

ssize_t encrypt_write(int fd, const void *buf, size_t bytes)
{
	ssize_t result = 0;

	pthread_mutex_lock(&filemap_lock);
	struct filemap_s *file = file_from_fd(fd);

	if (file) {
		assert(file->state == WRITE);
		const unsigned char *source = buf;

		if (bytes > 0 && file->position < sizeof(struct file_header_s)) {
			// first consume the header from the caller
			size_t to_consume = sizeof(struct file_header_s) - file->position;
			if (to_consume > bytes) to_consume = bytes;
			char *target = (char *)&file->header + file->position;
			memcpy(target, source, to_consume);
			source += to_consume;
			result += to_consume;
			bytes -= to_consume;
			file->position += to_consume;
		}

		if (bytes > 0 && file->position == sizeof(struct file_header_s)) {
			// start the crypto context
			int gcm_result = mbedtls_gcm_starts(&file->gcm, MBEDTLS_GCM_DECRYPT, file->header.iv, sizeof(file->header.iv));
			assert(gcm_result == 0);
		}

		if (bytes > 0 && file->position < file->header.trailer_start) {
			// consume and decrypt file content from the caller
			size_t to_consume = file->header.trailer_start - file->position;
			if (to_consume > bytes) to_consume = bytes;
			size_t enlarged = to_consume + 15;  // mbedtls needs a rounded-up output buffer
			buffer_alloc(&file->content_buffer, enlarged);

			// perform decryption
			unsigned char *target = (unsigned char *)file->content_buffer.buffer;
			size_t gcm_size;
			int gcm_result = mbedtls_gcm_update(&file->gcm, source, to_consume, target, enlarged, &gcm_size);
			assert(gcm_result == 0);

			// write file data
			size_t to_write = gcm_size;
			const char *buffer = file->content_buffer.buffer;
			while (to_write > 0) {
				ssize_t write_result = write(fd, buffer, to_write);
				if (write_result < 0 && errno == EINTR) continue;
				if (write_result < 0) return write_result;
				buffer += write_result;
				to_write -= (size_t)write_result;
			}

			source += to_consume;
			result += to_consume;
			bytes -= to_consume;
			file->position += to_consume;
		}

		if (bytes > 0 && file->position >= file->header.trailer_start) {
			// lastly consume the file trailer from the caller
			size_t to_consume = sizeof(struct file_trailer_s);
			to_consume -= file->position - file->header.trailer_start;
			if (to_consume > bytes) to_consume = bytes;
			char *target = (char *)&file->trailer;
			target += file->position - file->header.trailer_start;
			memcpy(target, source, to_consume);
			result += to_consume;
			file->position += to_consume;
		}

		if (file->position == file->header.trailer_start + sizeof(struct file_trailer_s)) {
			// verify authentication tag
			buffer_alloc(&file->content_buffer, 15);
			unsigned char *target = (unsigned char *)file->content_buffer.buffer;
			unsigned char generated[128 / CHAR_BIT];
			size_t gcm_size;
			int gcm_result = mbedtls_gcm_finish(&file->gcm, target, bytes, &gcm_size, generated, sizeof(generated));
			assert(gcm_result == 0);

			if (gcm_size > 0) {
				// write file data
				size_t to_write = gcm_size;
				const char *buffer = file->content_buffer.buffer;
				while (to_write > 0) {
					ssize_t write_result = write(fd, buffer, to_write);
					if (write_result < 0 && errno == EINTR) continue;
					if (write_result < 0) return write_result;
					buffer += write_result;
					to_write -= (size_t)write_result;
				}
			}

			int diff = memcmp(file->trailer.auth_tag, generated, sizeof(struct file_trailer_s));
			if (diff != 0) return EIO;
		}

	} else {
		result = write(fd, buf, bytes);
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
		if (file->state != CLOSE) mbedtls_gcm_free(&file->gcm);
		free(file->path);
		free(file->content_buffer.buffer);
		free(file);
	}
	filemap = NULL;

	pthread_mutex_unlock(&filemap_lock);
}
