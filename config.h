/* intercept layer that parses config files as they are read by Unison */

#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>

struct string_s {
	char *string;
	size_t length;
};

extern struct config_s {
	pthread_mutex_t lock;
	char *search_path;
	struct string_s root[2];
	char *pre_command;
	char *post_command;
	struct post_s {
		struct string_s pattern;
		char *command;
		struct post_s *next;
	} *post;
	struct symlink_s {
		struct string_s path;
		char *target;
		struct symlink_s *next;
	} *symlink;
	struct encrypt_s {
		struct string_s path;
		unsigned char key[256 / CHAR_BIT];
		struct encrypt_s *next;
	} *encrypt;
	struct buffer_s {
		char *buffer;
		size_t size;
	} scratchpad;
} config;

static inline void buffer_alloc(struct buffer_s * restrict buffer, size_t size)
{
	if (buffer->size < size) {
		size = (size + 1024) & ~1023U;
		buffer->buffer = realloc(buffer->buffer, size);
		assert(buffer->buffer);
		buffer->size = size;
	}
}


int config_open(const char *path, int flags, ...);
int config_close(int fd);
ssize_t config_read(int fd, void *buf, size_t bytes);

void config_reset(void);
