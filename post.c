#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <fnmatch.h>
#include <dirent.h>
#include <fcntl.h>
#include <sysexits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>

#include "config.h"
#include "post.h"

#define ARCHIVE_PATTERN "*/ar[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]"


static char *current_archive = NULL;

static void postcmd_remember_archive(const char *path);
static void postcmd_check_finalize(const char *path);
static void post_recurse(const char *path);
static void post_check(const char *path);
static void post_run(const char *command, const char *path);


/* MARK: - Intercepted Functions */

int post_open(const char *path, int flags, ...)
{
	postcmd_remember_archive(path);

	int result;
	va_list arg;
	va_start(arg, flags);

	if (flags & O_CREAT) {
		mode_t mode = (mode_t)va_arg(arg, unsigned);
		result = open(path, flags, mode);
	} else {
		result = open(path, flags);
	}

	va_end(arg);
	return result;
}

int post_stat(const char * restrict path, struct stat * restrict buf)
{
	postcmd_remember_archive(path);
	return stat(path, buf);
}

int post_lstat(const char * restrict path, struct stat * restrict buf)
{
	postcmd_remember_archive(path);
	return lstat(path, buf);
}

int post_rename(const char *old, const char *new)
{
	postcmd_check_finalize(new);
	int result = rename(old, new);
	if (result == 0)
		post_recurse(new);
	return result;
}

int post_unlink(const char *path)
{
	postcmd_check_finalize(path);
	int result = unlink(path);
	if (result == 0)
		post_check(path);
	return result;
}

int post_rmdir(const char *path)
{
	int result = rmdir(path);
	if (result == 0)
		post_check(path);
	return result;
}


/* MARK: - Helper Functions */

static void postcmd_remember_archive(const char *path)
{
	if (config.post_command && !current_archive && fnmatch(ARCHIVE_PATTERN, path, 0) == 0)
		current_archive = strdup(path);
}

static void postcmd_check_finalize(const char *path)
{
	if (config.post_command && current_archive && strcmp(path, current_archive) == 0) {
		// final update to archive file, run post command
		pthread_mutex_lock(&config.lock);
		post_run(config.post_command, NULL);
		pthread_mutex_unlock(&config.lock);
		post_reset();
	}
}

static void post_recurse(const char *path)
{
	post_check(path);

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

static void post_check(const char *path)
{
	pthread_mutex_lock(&config.lock);
	for (struct post_s *post = config.post; post; post = post->next) {
		for (size_t i = 0; i < sizeof(config.root) / sizeof(config.root[0]); i++) {
			if (config.root[i].string) {
				size_t size = config.root[i].length + sizeof("/") + post->pattern.length;
				scratchpad_alloc(&config.scratchpad, size);
				sprintf(config.scratchpad.buffer, "%s/%s", config.root[i].string, post->pattern.string);
				if (fnmatch(config.scratchpad.buffer, path, FNM_PATHNAME) == 0)
					post_run(post->command, path);
			}
		}
	}
	pthread_mutex_unlock(&config.lock);
}

static void post_run(const char *const_command, const char *path)
{
	char *command = strdup(const_command);
	size_t length = strlen(const_command);

	// separate command string at spaces into arguments
	unsigned num_spaces = 0;
	for (size_t i = 0; i < length; i++)
		if (command[i] == ' ') num_spaces++;

	const char ** const arguments = malloc((num_spaces + 3) * sizeof(char *));

	size_t arg = 0;
	for (size_t i = 0; i < length; i++) {
		if (command[i] == ' ') command[i] = '\0';
		if (i == 0 || command[i-1] == '\0') {
			arguments[arg] = command + i;
			if (command[i] != '\0') arg++;  // handle multiple spaces
		}
	}
	arguments[arg++] = path;
	arguments[arg++] = NULL;

	pid_t pid = fork();
	if (pid == 0) {
		// child
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
		execvP(command, config.search_path, (char **)arguments);
#pragma clang diagnostic pop
		_exit(EX_UNAVAILABLE);
	} else if (pid > 0) {
		// parent
		waitpid(pid, NULL, 0);
	} else {
		fputs("failed to execute post command\n", stderr);
	}

	free(arguments);
	free(command);
}

void post_reset(void)
{
	free(current_archive);
	current_archive = NULL;
}
