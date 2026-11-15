#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

typedef int (*compare_function)(const char *, const char *);
typedef int (*open_function)(const char *, int, ...);
typedef time_t (*clock_function)(time_t *);

int strcmp(const char *left, const char *right) {
    compare_function original = (compare_function)dlsym(RTLD_NEXT, "strcmp");
    const char *prefix = getenv("REA_LICENSE_PREFIX");
    if (prefix != NULL && *prefix != '\0' && strstr(left, prefix) != NULL && strstr(right, prefix) != NULL) return 0;
    if (original != NULL) return original(left, right);
    while (*left && *left == *right) { left++; right++; }
    return (unsigned char)*left - (unsigned char)*right;
}

int open(const char *path, int flags, ...) {
    open_function original = (open_function)dlsym(RTLD_NEXT, "open");
    if (original == NULL) { errno = ENOSYS; return -1; }
    int needs_mode = (flags & O_CREAT) != 0;
#ifdef O_TMPFILE
    needs_mode |= (flags & O_TMPFILE) == O_TMPFILE;
#endif
    mode_t mode = 0;
    if (needs_mode) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    const char *replacement = getenv("REA_MACHINE_ID_FILE");
    const char *selected = replacement != NULL && strstr(path, "machine-id") != NULL ? replacement : path;
    return needs_mode ? original(selected, flags, mode) : original(selected, flags);
}

time_t time(time_t *output) {
    clock_function original = (clock_function)dlsym(RTLD_NEXT, "time");
    const char *configured = getenv("REA_FIXED_TIME");
    if (configured == NULL) {
        if (original != NULL) return original(output);
        errno = ENOSYS;
        return (time_t)-1;
    }
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(configured, &end, 10);
    if (errno != 0 || *configured == '\0' || *end != '\0') { errno = EINVAL; return (time_t)-1; }
    time_t fixed = (time_t)parsed;
    if ((long long)fixed != parsed) { errno = EOVERFLOW; return (time_t)-1; }
    if (output != NULL) *output = fixed;
    return fixed;
}
