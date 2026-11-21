/*
 * rasp_syscall.c —— 直调 syscall 引擎实现
 *
 * 每个封装都做完整的返回值校验：内核返回 -errno 时统一转成 -1 + errno，
 * 调用方必须检查 errno（见《生成要求》③-3）。
 */
#include "rasp_syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int neg_to_errno(long ret)
{
    if (ret < 0 && ret > -4096) {
        errno = (int)-ret;
        return -1;
    }
    return 0;
}

int rasp_raw_open(const char *path, int flags, int mode)
{
    return rasp_raw_openat(RASP_AT_FDCWD, path, flags, mode);
}

int rasp_raw_openat(int dirfd, const char *path, int flags, int mode)
{
    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }
    long ret = rasp_raw_syscall4(SYS_OPENAT, dirfd, (long)path, flags, mode);
    if (neg_to_errno(ret) != 0) return -1;
    return (int)ret;
}

long rasp_raw_read(int fd, void *buf, size_t count)
{
    if (buf == NULL) {
        errno = EINVAL;
        return -1;
    }
    long ret = rasp_raw_syscall3(SYS_READ, fd, (long)buf, (long)count);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

int rasp_raw_close(int fd)
{
    long ret = rasp_raw_syscall1(SYS_CLOSE, fd);
    if (neg_to_errno(ret) != 0) return -1;
    return 0;
}

long rasp_raw_getdents64(int fd, void *buf, size_t count)
{
    long ret = rasp_raw_syscall3(SYS_GETDENTS64, fd, (long)buf, (long)count);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

long rasp_raw_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    long ret = rasp_raw_syscall4(SYS_READLINKAT, dirfd, (long)path, (long)buf, (long)bufsiz);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

int rasp_raw_statx(int dirfd, const char *path, int flags, unsigned int mask, struct rasp_statx *stx)
{
    long ret = rasp_raw_syscall5(SYS_STATX, dirfd, (long)path, flags, mask, (long)stx);
    if (neg_to_errno(ret) != 0) return -1;
    return 0;
}

int rasp_raw_pidfd_open(pid_t pid, unsigned int flags)
{
    long ret = rasp_raw_syscall2(SYS_PIDFD_OPEN, pid, flags);
    if (neg_to_errno(ret) != 0) return -1;
    return (int)ret;
}

int rasp_pidfd_open_compat(pid_t pid)
{
    int fd = rasp_raw_pidfd_open(pid, 0);
    if (fd < 0) {
        /* 内核 < 5.3 或 seccomp 限制时回退：普通 openat 打不开进程目录，返回 -1 由调用方降级 */
        return -1;
    }
    return fd;
}

long rasp_raw_clone3(struct rasp_clone_args *args, size_t size)
{
    long ret = rasp_raw_syscall2(SYS_CLONE3, (long)args, (long)size);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

long rasp_raw_clone(unsigned long flags, void *child_stack)
{
    long ret = rasp_raw_syscall5(SYS_CLONE, flags, (long)child_stack, 0, 0, 0);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

int rasp_raw_memfd_create(const char *name, unsigned int flags)
{
    long ret = rasp_raw_syscall2(SYS_MEMFD_CREATE, (long)name, flags);
    if (neg_to_errno(ret) != 0) return -1;
    return (int)ret;
}

void *rasp_raw_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    long ret = rasp_raw_syscall6(SYS_MMAP, (long)addr, (long)len, prot, flags, fd, (long)off);
    if (ret < 0 && ret > -4096) {
        errno = (int)-ret;
        return (void *)-1;
    }
    return (void *)ret;
}

long rasp_raw_wait4(pid_t pid, int *status, int options, void *rusage)
{
    long ret = rasp_raw_syscall4(SYS_WAIT4, pid, (long)status, options, (long)rusage);
    if (neg_to_errno(ret) != 0) return -1;
    return ret;
}

int rasp_raw_kill(pid_t pid, int sig)
{
    long ret = rasp_raw_syscall2(SYS_KILL, pid, sig);
    if (neg_to_errno(ret) != 0) return -1;
    return 0;
}

void rasp_raw_exit_group(int code)
{
    (void)rasp_raw_syscall1(SYS_EXIT_GROUP, code);
    for (;;) {
        /* 不可达 */
    }
}

pid_t rasp_raw_getpid(void)
{
    return (pid_t)rasp_raw_syscall0(SYS_GETPID);
}

pid_t rasp_raw_gettid(void)
{
    return (pid_t)rasp_raw_syscall0(SYS_GETTID);
}

uid_t rasp_raw_getuid(void)
{
    return (uid_t)rasp_raw_syscall0(SYS_GETUID);
}

uid_t rasp_raw_geteuid(void)
{
    return (uid_t)rasp_raw_syscall0(SYS_GETEUID);
}

long rasp_raw_clock_gettime(int clk, struct rasp_timespec *ts)
{
    if (ts == NULL) {
        errno = EINVAL;
        return -1;
    }
    long ret = rasp_raw_syscall2(SYS_CLOCK_GETTIME, clk, (long)ts);
    if (neg_to_errno(ret) != 0) return -1;
    return 0;
}

int rasp_raw_statfs(const char *path, struct rasp_statfs *out)
{
    if (path == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    long ret = rasp_raw_syscall2(SYS_STATFS, (long)path, (long)out);
    if (neg_to_errno(ret) != 0) return -1;
    return 0;
}

int rasp_raw_openat2(int dirfd, const char *path, struct rasp_open_how *how, size_t size)
{
    if (path == NULL || how == NULL) {
        errno = EINVAL;
        return -1;
    }
    long ret = rasp_raw_syscall4(SYS_OPENAT2, dirfd, (long)path, (long)how, (long)size);
    if (neg_to_errno(ret) != 0) return -1;
    return (int)ret;
}
