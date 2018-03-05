/* libSystem intercept layer that parses config files as they are read by Unison */

#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

struct string_s {
	char *string;
	size_t length;
};

extern struct config_s {
	pthread_mutex_t lock;
	char *search_path;
	struct string_s root[2];
	struct post_s {
		struct string_s file;
		char *command;
		struct post_s *next;
	} *post;
	struct buffer_s {
		char *string;
		size_t size;
	} scratchpad;
} config;

static inline void scratchpad_alloc(struct buffer_s *scratchpad, size_t size)
{
	if (scratchpad->size < size) {
		size = (size + 1024) & ~1023;
		scratchpad->string = realloc(scratchpad->string, size);
		assert(scratchpad->string);
		scratchpad->size = size;
	}
}


int config_open(const char *path, int flags, ...);
int config_close(int fd);
ssize_t config_read(int fd, void *buf, size_t bytes);
