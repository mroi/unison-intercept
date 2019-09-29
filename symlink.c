#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#include "config.h"
#include "symlink.h"


static pthread_mutex_t dirmap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dirmap_s {
	const DIR *dir;
	char *path;
	struct dirmap_s *next;
} *dirmap = NULL;

static void symlink_iterate(const char *path, void (*)(const struct string_s path, const struct string_s link, const char *target));
static void symlink_prepare(const struct string_s path, const struct string_s link, const char *target);
static void symlink_cleanup(const struct string_s path, const struct string_s link, const char *target);
static void symlink_prepare_children(const struct string_s path, const struct string_s link, const char *target);
static void symlink_cleanup_children(const struct string_s path, const struct string_s link, const char *target);


/* MARK: - Intercepted Functions */

int symlink_stat(const char * restrict path, struct stat * restrict buf)
{
	symlink_iterate(path, symlink_prepare);
	int result = stat(path, buf);
	symlink_iterate(path, symlink_cleanup);
	return result;
}

int symlink_lstat(const char * restrict path, struct stat * restrict buf)
{
	symlink_iterate(path, symlink_prepare);
	int result = lstat(path, buf);
	symlink_iterate(path, symlink_cleanup);
	return result;
}

DIR *symlink_opendir(const char *path)
{
	symlink_iterate(path, symlink_prepare_children);
	DIR *dir = opendir(path);

	// remember mapping from dir to path for cleanup
	pthread_mutex_lock(&dirmap_lock);
	struct dirmap_s *entry = malloc(sizeof(struct dirmap_s));
	entry->dir = dir;
	entry->path = strdup(path);
	entry->next = dirmap;
	dirmap = entry;
	pthread_mutex_unlock(&dirmap_lock);

	return dir;
}

int symlink_closedir(DIR *dir)
{
	int result = closedir(dir);

	// pull path information from dirmap
	pthread_mutex_lock(&dirmap_lock);
	struct dirmap_s *entry, **prev = &dirmap;
	for (entry = dirmap; entry; entry = entry->next) {
		if (entry->dir == dir) break;
		prev = &entry->next;
	}
	assert(entry);
	*prev = entry->next;
	pthread_mutex_unlock(&dirmap_lock);

	symlink_iterate(entry->path, symlink_cleanup_children);
	free(entry->path);
	free(entry);

	return result;
}


/* MARK: - Helper Functions */

static void symlink_iterate(const char *path, void (*f)(const struct string_s path, const struct string_s link, const char *target))
{
	const size_t path_length = strlen(path);

	pthread_mutex_lock(&config.lock);
	for (struct symlink_s *link = config.symlink; link; link = link->next) {
		if (config.root[1].string) {
			size_t size = config.root[1].length + sizeof("/") + link->path.length;
			scratchpad_alloc(&config.scratchpad, size);
			sprintf(config.scratchpad.buffer, "%s/%s", config.root[1].string, link->path.string);

			if (strncmp(path, config.scratchpad.buffer, path_length) == 0) {
				// path is a prefix of the link directive
				const struct string_s path_string = {
					.string = strdup(path),
					.length = path_length
				};
				const struct string_s link_string = {
					.string = config.scratchpad.buffer,
					.length = size
				};
				f(path_string, link_string, link->target);
				// f may manipulate its argument strings in-place
				free(path_string.string);
			}
		}
	}
	pthread_mutex_unlock(&config.lock);
}

static void symlink_prepare(const struct string_s path, const struct string_s link, const char *target)
{
	if (path.length < link.length && link.string[path.length] == '/') {
		// path is a proper parent directory of the link directive
		mkdir(path.string, S_IRWXU | S_IRWXG | S_IRWXO);
	} else if (path.length == link.length) {
		// since we know path is a prefix, we now know path is equal to the link directive
		symlink(target, path.string);
	}
}

static void symlink_cleanup(const struct string_s path, const struct string_s link, const char *target)
{
	(void)target;
	if (path.length == link.length) {
		// since we know path is a prefix, we now know path is equal to the link directive
		struct stat s;
		bool is_symlink = lstat(path.string, &s) == 0 && (s.st_mode & S_IFLNK);
		bool is_broken = is_symlink && stat(path.string, &s) != 0 && errno == ENOENT;
		if (is_broken) unlink(path.string);
	}
}

static void symlink_prepare_children(const struct string_s path, const struct string_s link, const char *target)
{
	if (path.length < link.length && link.string[path.length] == '/') {
		// path is a proper parent directory of the link directive
		const char *child_path = link.string + path.length + 1;
		char *next_slash = strchr(child_path, '/');

		if (next_slash) {
			// more subdirectories to come, create next directory level
			*next_slash = '\0';
			mkdir(link.string, S_IRWXU | S_IRWXG | S_IRWXO);
		} else {
			// child is last path element, create symlink
			symlink(target, link.string);
		}
	}
}

static void symlink_cleanup_children(const struct string_s path, const struct string_s link, const char *target)
{
	(void)target;
	if (path.length < link.length && link.string[path.length] == '/') {
		// path is a proper parent directory of the link directive
		const char *child_path = link.string + path.length + 1;
		char *next_slash = strchr(child_path, '/');

		if (!next_slash) {
			// child is last path element, check symlink
			struct stat s;
			bool is_symlink = lstat(link.string, &s) == 0 && (s.st_mode & S_IFLNK);
			bool is_broken = is_symlink && stat(link.string, &s) != 0 && errno == ENOENT;
			if (is_broken) {
				unlink(link.string);
				// unlink empty parent directories
				do {
					char *last_slash = strrchr(link.string, '/');
					if (last_slash) *last_slash = '\0';
				} while (rmdir(link.string) == 0);
			}
		}
	}
}

void symlink_reset(void)
{
	pthread_mutex_lock(&dirmap_lock);

	struct dirmap_s *next;
	for (struct dirmap_s *entry = dirmap; entry; entry = next) {
		next = entry->next;
		free(entry->path);
		free(entry);
	}
	dirmap = NULL;

	pthread_mutex_unlock(&dirmap_lock);
}
