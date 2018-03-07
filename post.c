#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>

#include "config.h"
#include "post.h"


static void post_recurse(const char *path);
static void post_check_and_run(const char *path);


/* MARK: - Intercepted Functions */

int post_rename(const char *old, const char *new)
{
	int result = rename(old, new);
	if (result == 0)
		post_recurse(new);
	return result;
}

int post_unlink(const char *path)
{
	int result = unlink(path);
	if (result == 0)
		post_check_and_run(path);
	return result;
}

int post_rmdir(const char *path)
{
	int result = rmdir(path);
	if (result == 0)
		post_check_and_run(path);
	return result;
}


/* MARK: - Helper Functions */

static void post_recurse(const char *path)
{
	post_check_and_run(path);

	struct stat statbuf;
	if (lstat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
		DIR *dir = opendir(path);
		struct dirent entry;
		struct dirent *result = &entry;
		struct buffer_s recursion = { .buffer = NULL, .size = 0 };
		while (readdir_r(dir, &entry, &result) == 0 && result) {
			if (strcmp(entry.d_name, ".") == 0 || strcmp(entry.d_name, "..") == 0)
				continue;
			size_t size = strlen(path) + strlen(entry.d_name) + sizeof('/') + sizeof('\0');
			scratchpad_alloc(&recursion, size);
			assert(recursion.buffer);  // help the static analyzer
			sprintf(recursion.buffer, "%s/%s", path, entry.d_name);
			post_recurse(recursion.buffer);
		}
		free(recursion.buffer);
		closedir(dir);
	}
}

static void post_check_and_run(const char *path)
{
	pthread_mutex_lock(&config.lock);
	for (struct post_s *post = config.post; post; post = post->next) {
		for (size_t i = 0; i < sizeof(config.root) / sizeof(config.root[0]); i++) {
			if (config.root[i].string) {
				size_t size = config.root[i].length + sizeof("/") + post->pattern.length;
				scratchpad_alloc(&config.scratchpad, size);
				sprintf(config.scratchpad.buffer, "%s/%s", config.root[i].string, post->pattern.string);
				if (fnmatch(config.scratchpad.buffer, path, FNM_PATHNAME) == 0) {

					// match found, run the post command
					pid_t pid = fork();
					if (pid == 0) {
						// child
						const char * const arguments[] = {
							post->command, path, NULL
						};
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
						execvP(post->command, config.search_path, (char * const *)arguments);
#pragma clang diagnostic pop
						_exit(EX_UNAVAILABLE);
					} else if (pid > 0) {
						// parent
						waitpid(pid, NULL, 0);
					} else {
						fputs("failed to execute post command\n", stderr);
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&config.lock);
}
