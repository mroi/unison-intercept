#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <fnmatch.h>
#include <paths.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifndef __APPLE__
#define strlcpy strncpy
#endif

#include "config.h"
#include "mbedtls/sha256.h"

#define UNISON_DIR1 ".unison"
#define UNISON_DIR2 "Library/Application Support/Unison"

enum entry_type {
	ENTRY_ROOT,
	ENTRY_PRE_CMD, ENTRY_POST_CMD, ENTRY_POST_PATH,
	ENTRY_SYMLINK,
	ENTRY_ENCRYPT
};


static bool config_expected = true;
static char *config_pattern;
static int current_config_fd = -1;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
static struct parse_s {
	const enum entry_type type;
	const char * const pattern;
	size_t seen;
} parse[] = {
	/* uses a minimal regexp syntax:
	 *  ^ - beginning of line
	 *  * - previous symbol repeats
	 *  . - matches anything, stores in argument buffer
	 *    - space also matches tab */
	{ .type = ENTRY_ROOT, .pattern = "^root *= *.*" },
	{ .type = ENTRY_PRE_CMD, .pattern = "^#precmd *= *.*" },
	{ .type = ENTRY_POST_CMD, .pattern = "^#postcmd *= *.*" },
	{ .type = ENTRY_POST_PATH, .pattern = "^#post *= *Path *.*" },
	{ .type = ENTRY_SYMLINK, .pattern = "^#symlink *= *Path *.*" },
	{ .type = ENTRY_ENCRYPT, .pattern = "^#encrypt *= *Path *.*" }
};
#pragma clang diagnostic pop
static struct buffer_s argument = { .buffer = NULL, .size = 0 };

struct config_s config = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.search_path = NULL,
	.root = { { .string = NULL, .length = 0 }, { .string = NULL, .length = 0 } },
	.pre_command = NULL,
	.post_command = NULL,
	.post = NULL,
	.symlink = NULL,
	.encrypt = NULL,
	.scratchpad = { .buffer = NULL, .size = 0 }
};

static void config_parse(struct parse_s * restrict parser, char character);
static void process_entry(enum entry_type type);


static void __attribute__((constructor)) initialize(void)
{
	char *config_prefix;
	size_t alloc_size;

	// determine the path where Unison’s config files live
	const char *envvar = getenv("UNISON");
	if (envvar) {
		alloc_size = strlen(envvar) + sizeof("/*");
		config_prefix = malloc(alloc_size);
		if (!config_prefix) abort();
		strlcpy(config_prefix, envvar, alloc_size);
	} else {
		const char *home = getenv("HOME");
		assert(home);
		alloc_size = strlen(home) + sizeof("/" UNISON_DIR1 "/*");
		config_prefix = malloc(alloc_size);
		if (!config_prefix) abort();
		snprintf(config_prefix, alloc_size, "%s/" UNISON_DIR1, home);
		struct stat statbuf;
		if (stat(config_prefix, &statbuf) != 0) {
			alloc_size = strlen(home) + sizeof("/" UNISON_DIR2 "/*");
			config_prefix = realloc(config_prefix, alloc_size);
			if (!config_prefix) abort();
			snprintf(config_prefix, alloc_size, "%s/" UNISON_DIR2, home);
		}
	}

	// amend PATH with Unison’s bin directory
	alloc_size = 2 * strlen(config_prefix) + sizeof(":/bin:" _PATH_DEFPATH);
	config.search_path = malloc(alloc_size);
	if (!config.search_path) abort();
	snprintf(config.search_path, alloc_size, "%s:%s/bin:" _PATH_DEFPATH, config_prefix, config_prefix);

	// set pattern to detect opening of configuration files
	strcat(config_prefix, "/*");
	config_pattern = config_prefix;

	// test crypto functionality
	assert(mbedtls_sha256_self_test(0) == 0);
}

static void __attribute__((destructor)) finalize(void)
{
	config_reset();
	free(config.search_path);
	free(config.scratchpad.buffer);

	free(config_pattern);
	free(argument.buffer);
}


/* MARK: - Intercepted Functions */

int config_open(const char *path, int flags, ...)
{
	int result;
	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT) {
		mode_t mode = (mode_t)va_arg(arg, unsigned);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);

		if (result >= 0 && (flags & O_ACCMODE) == O_RDONLY && config_expected &&
			fnmatch(config_pattern, path, FNM_PATHNAME) == 0) {

			if (strlen(strrchr(path, '/') + 1) == 2 + 32) {
				// unison internal file, sync has started, inhibit parsing of upcoming files
				config_expected = false;
			} else {
				assert(current_config_fd == -1);  // config files must be read sequentially
				current_config_fd = result;

				// reset config parser
				for (size_t i = 0; i < sizeof(parse) / sizeof(parse[0]); i++) {
					parse[i].seen = 0;
					config_parse(&parse[i], '\n');
				}
				buffer_alloc(&argument, 1);
				argument.buffer[0] = '\0';
			}
		}
	}

	va_end(arg);
	return result;
}

int config_close(int fd)
{
	if (fd == current_config_fd)
		current_config_fd = -1;
	return close(fd);
}

ssize_t config_read(int fd, void *buf, size_t bytes)
{
	ssize_t result = read(fd, buf, bytes);

	if (result > 0 && fd == current_config_fd)
		for (ssize_t pos = 0; pos < result; pos++)
			for (size_t i = 0; i < sizeof(parse) / sizeof(parse[0]); i++)
				config_parse(&parse[i], ((char *)buf)[pos]);
	if (result == 0 && bytes > 0 && fd == current_config_fd)
		// finalize parsing when last line has no trailing newline
		for (size_t i = 0; i < sizeof(parse) / sizeof(parse[0]); i++)
			config_parse(&parse[i], '\n');

	return result;
}


/* MARK: - Helper Functions */

static void config_parse(struct parse_s * restrict parser, char character)
{
	switch (parser->pattern[parser->seen]) {
	case '^':
		if (character == '\n') {
			parser->seen++;
		} else if (parser->seen) {
			parser->seen = 0;
			config_parse(parser, character);
		}
		break;
	case ' ':
		if (character == ' ' || character == '\t') {
			parser->seen++;
		} else if (parser->seen) {
			parser->seen = 0;
			config_parse(parser, character);
		}
		break;
	case '.':
		if (character != '\n') {
			size_t length = strlen(argument.buffer);
			buffer_alloc(&argument, length + 1);
			argument.buffer[length + 0] = character;
			argument.buffer[length + 1] = '\0';
			parser->seen++;
		} else if (parser->seen) {
			parser->seen = 0;
			config_parse(parser, character);
		}
		break;
	case '*': {
		size_t saved_state = parser->seen;
		parser->seen--;
		config_parse(parser, character);
		if (parser->seen != saved_state) {
			parser->seen = saved_state + 1;
			config_parse(parser, character);
		}
		break;
	}
	case '\0':
		process_entry(parser->type);
		parser->seen = 0;
		config_parse(parser, character);
		break;
	default:
		if (character == parser->pattern[parser->seen]) {
			parser->seen++;
		} else if (parser->seen) {
			parser->seen = 0;
			config_parse(parser, character);
		}
		break;
	}
}

static void process_entry(enum entry_type type)
{
	if (!argument.buffer) return;

	for (char *c = argument.buffer + strlen(argument.buffer) - 1; c > argument.buffer; c--)
		if (*c == ' ') *c = '\0';
		else break;

	char *attribute = NULL;
	char *separator = strstr(argument.buffer, " -> ");
	if (separator) {
		for (char *c = separator; c > argument.buffer; c--)
			if (*c == ' ') *c = '\0';
			else break;
		for (attribute = separator + sizeof(" ->"); *attribute != '\0'; attribute++)
			if (*attribute != ' ') break;
	}

	switch (type) {
	case ENTRY_ROOT:
		if (argument.buffer[0] != '/') break;
		for (char *c = argument.buffer + strlen(argument.buffer) - 1; c > argument.buffer; c--)
			if (*c == '/') *c = '\0';
			else break;
		pthread_mutex_lock(&config.lock);
		if (!config.root[0].string) {
			config.root[0].string = strdup(argument.buffer);
			config.root[0].length = strlen(argument.buffer);
		} else if (!config.root[1].string) {
			config.root[1].string = strdup(argument.buffer);
			config.root[1].length = strlen(argument.buffer);
		}
		pthread_mutex_unlock(&config.lock);
		break;

	case ENTRY_PRE_CMD:
		if (argument.buffer[0] == '\0') break;
		pthread_mutex_lock(&config.lock);
		if (config.pre_command) free(config.pre_command);
		config.pre_command = strdup(argument.buffer);
		pthread_mutex_unlock(&config.lock);
		break;

	case ENTRY_POST_CMD:
		if (argument.buffer[0] == '\0') break;
		pthread_mutex_lock(&config.lock);
		if (config.post_command) free(config.post_command);
		config.post_command = strdup(argument.buffer);
		pthread_mutex_unlock(&config.lock);
		break;

	case ENTRY_POST_PATH:
		if (!attribute) break;
		struct post_s *new_post = malloc(sizeof(struct post_s));
		if (!new_post) break;
		new_post->pattern.string = strdup(argument.buffer);
		new_post->pattern.length = strlen(argument.buffer);
		new_post->command = strdup(attribute);
		new_post->next = NULL;
		pthread_mutex_lock(&config.lock);
		// append at the end causes O(n²) complexity, but ensures processing in config file order
		struct post_s **last_post;
		for (last_post = &config.post; *last_post; last_post = &(*last_post)->next) {}
		*last_post = new_post;
		pthread_mutex_unlock(&config.lock);
		break;

	case ENTRY_SYMLINK:
		if (!attribute) break;
		struct symlink_s *new_link = malloc(sizeof(struct symlink_s));
		if (!new_link) break;
		new_link->path.string = strdup(argument.buffer);
		new_link->path.length = strlen(argument.buffer);
		new_link->target = strdup(attribute);
		new_link->next = NULL;
		pthread_mutex_lock(&config.lock);
		// ordering by length causes O(n²) complexity, but ensures processing in path nesting order
		struct symlink_s **cur_link;
		for (cur_link = &config.symlink; *cur_link; cur_link = &(*cur_link)->next) {
			if ((*cur_link)->path.length > new_link->path.length) break;
		}
		new_link->next = *cur_link;
		*cur_link = new_link;
		pthread_mutex_unlock(&config.lock);
		break;

	case ENTRY_ENCRYPT:
		if (!attribute) break;
		if (strncmp(attribute, "aes-256-gcm:", sizeof("aes-256-gcm:") - sizeof((char)'\0')) != 0) break;
		attribute += sizeof("aes-256-gcm:") - sizeof((char)'\0');
		struct encrypt_s *new_encrypt = malloc(sizeof(struct encrypt_s));
		if (!new_encrypt) break;
		new_encrypt->path.string = strdup(argument.buffer);
		new_encrypt->path.length = strlen(argument.buffer);
		// find the last slash to separate path and filename
		char *path, *name;
		name = strrchr(argument.buffer, '/');
		if (name) {
			name[0] = '\0';
			name++;
			path = argument.buffer;
		} else {
			name = argument.buffer;
			path = NULL;
		}
		// generate prefixed and suffixed versions of the filename
		size_t alloc_size = sizeof(".unison.") - sizeof((char)'\0') + new_encrypt->path.length + sizeof(".*");
		new_encrypt->prefixed_path.length = alloc_size - sizeof((char)'\0');
		new_encrypt->prefixed_path.string = malloc(alloc_size);
		assert(new_encrypt->prefixed_path.string);
		snprintf(new_encrypt->prefixed_path.string, alloc_size,
		         path ? "%s/.unison.%s.*" : "%.0s.unison.%s.*", path, name);
		alloc_size = new_encrypt->path.length + sizeof(".unison.*");
		new_encrypt->suffixed_path.length = alloc_size - sizeof((char)'\0');
		new_encrypt->suffixed_path.string = malloc(alloc_size);
		assert(new_encrypt->suffixed_path.string);
		snprintf(new_encrypt->suffixed_path.string, alloc_size,
		         path ? "%s/%s.unison.*" : "%.0s%s.unison.*", path, name);
		// process the key material with SHA-256 to obtain an AES-256 key
		mbedtls_sha256((unsigned char *)attribute, strlen(attribute), new_encrypt->key, 0);
		new_encrypt->next = NULL;
		pthread_mutex_lock(&config.lock);
		// ordering by descending overall path length causes O(n²) complexity,
		// but ensures first match is most specific
		struct encrypt_s **cur_encrypt;
		for (cur_encrypt = &config.encrypt; *cur_encrypt; cur_encrypt = &(*cur_encrypt)->next) {
			if ((*cur_encrypt)->path.length < new_encrypt->path.length) break;
		}
		new_encrypt->next = *cur_encrypt;
		*cur_encrypt = new_encrypt;
		pthread_mutex_unlock(&config.lock);
		break;
	}

	argument.buffer[0] = '\0';
}

void config_reset(void)
{
	pthread_mutex_lock(&config.lock);

	for (size_t i = 0; i < sizeof(config.root) / sizeof(config.root[0]); i++) {
		free(config.root[i].string);
		config.root[i].string = NULL;
		config.root[i].length = 0;
	}

	free(config.pre_command);
	config.pre_command = NULL;
	free(config.post_command);
	config.post_command = NULL;

	for (struct post_s *post = config.post; post;) {
		free(post->pattern.string);
		free(post->command);
		struct post_s *save_post = post;
		post = post->next;
		free(save_post);
	}
	config.post = NULL;

	for (struct symlink_s *symlink = config.symlink; symlink;) {
		free(symlink->path.string);
		free(symlink->target);
		struct symlink_s *save_symlink = symlink;
		symlink = symlink->next;
		free(save_symlink);
	}
	config.symlink = NULL;

	for (struct encrypt_s *encrypt = config.encrypt; encrypt;) {
		free(encrypt->path.string);
		free(encrypt->prefixed_path.string);
		free(encrypt->suffixed_path.string);
		struct encrypt_s *save_encrypt = encrypt;
		encrypt = encrypt->next;
		free(save_encrypt);
	}
	config.encrypt = NULL;

	config_expected = true;

	pthread_mutex_unlock(&config.lock);
}
