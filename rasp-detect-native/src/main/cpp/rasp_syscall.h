/*
 * rasp_syscall.h —— 直调 syscall 引擎
 *
 * 目的：核心读取路径不经过 bionic libc 的 open/read/stat 包装函数，
 *       从而规避用户态 inline hook（LSPosed/Zygisk 模块最常见的 Hook 点）。
 * 实现：ARM64 用 svc #0，x86_64 用 syscall 指令，寄存器直接传参。
 * 约束：仅支持 aarch64 与 x86_64（本项目 abiFilters 已锁定）。
 */
#ifndef RASP_SYSCALL_H
#define RASP_SYSCALL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if !defined(__aarch64__) && !defined(__x86_64__)
#error "rasp_syscall: only aarch64 and x86_64 are supported"
#endif

/* ---------------- 系统调用号（Android 15 / Linux 5.15+ 通用 ABI） ---------------- */
#if defined(__aarch64__)
#define SYS_OPENAT 56
#define SYS_CLOSE 57
#define SYS_READ 63
#define SYS_GETDENTS64 61
#define SYS_READLINKAT 78
#define SYS_NEWFSTATAT 79
#define SYS_FSTAT 80
#define SYS_CLOCK_GETTIME 113
#define SYS_CLOCK_NANOSLEEP 115
#define SYS_KILL 129
#define SYS_GETPID 172
#define SYS_GETUID 174
#define SYS_GETEUID 175
#define SYS_GETTID 178
#define SYS_SOCKETPAIR 199
#define SYS_SENDTO 206
#define SYS_RECVFROM 207
#define SYS_MMAP 222
#define SYS_MUNMAP 215
#define SYS_WAIT4 260
#define SYS_STATX 291
#define SYS_MEMFD_CREATE 279
#define SYS_PIDFD_OPEN 434
#define SYS_CLONE3 435
#define SYS_OPENAT2 437
#define SYS_CLONE 220
#define SYS_EXIT_GROUP 94
#define SYS_TGKILL 131
#define SYS_FACCESSAT 48
#define SYS_STATFS 43
#else /* __x86_64__ */
#define SYS_READ 0
#define SYS_CLOSE 3
#define SYS_FSTAT 5
#define SYS_MMAP 9
#define SYS_GETPID 39
#define SYS_SOCKETPAIR 53
#define SYS_CLONE 56
#define SYS_WAIT4 61
#define SYS_KILL 62
#define SYS_EXIT_GROUP 231
#define SYS_GETUID 102
#define SYS_GETEUID 107
#define SYS_GETTID 186
#define SYS_READLINKAT 267
#define SYS_OPENAT 257
#define SYS_NEWFSTATAT 262
#define SYS_GETDENTS64 217
#define SYS_CLOCK_GETTIME 228
#define SYS_CLOCK_NANOSLEEP 230
#define SYS_TGKILL 234
#define SYS_MEMFD_CREATE 319
#define SYS_STATX 332
#define SYS_PIDFD_OPEN 434
#define SYS_CLONE3 435
#define SYS_OPENAT2 437
#define SYS_FACCESSAT 269
#define SYS_STATFS 137
#endif

/* ---------------- 常量（避免依赖可能被篡改的头文件） ---------------- */
#define RASP_AT_FDCWD (-100)
#define RASP_O_RDONLY 0
#define RASP_O_RDWR 2
#define RASP_O_CLOEXEC 02000000
#define RASP_O_NONBLOCK 04000
#define RASP_O_DIRECTORY 0200000

#define RASP_CLOCK_REALTIME 0
#define RASP_CLOCK_MONOTONIC 1
#define RASP_CLOCK_BOOTTIME 7

#define RASP_MAP_SHARED 0x01
#define RASP_MAP_PRIVATE 0x02
#define RASP_MAP_ANONYMOUS 0x20

#define RASP_SIGCHLD 17
#define RASP_SIGKILL 9

#define RASP_STATX_BASIC_STATS 0x000007ffU
#define RASP_AT_SYMLINK_NOFOLLOW 0x100
#define RASP_AT_EMPTY_PATH 0x1000

/* statx 结构（内核 uapi 布局，避免与 bionic <sys/stat.h> 的 struct stat 混用） */
struct rasp_statx_ts {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t __reserved;
};

struct rasp_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t __spare0[1];
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct rasp_statx_ts stx_atime;
    struct rasp_statx_ts stx_btime;
    struct rasp_statx_ts stx_ctime;
    struct rasp_statx_ts stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t __spare3[12];
};

struct rasp_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

/* ---------------- 原始系统调用 ---------------- */
static inline long rasp_raw_syscall0(long n)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
#else
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall1(long n, long a1)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
#else
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall2(long n, long a1, long a2)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory", "cc");
    return x0;
#else
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall3(long n, long a1, long a2, long a3)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
#else
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall4(long n, long a1, long a2, long a3, long a4)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
#else
    register long r10 __asm__("r10") = a4;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                     : "memory", "cc");
    return x0;
#else
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
#endif
}

static inline long rasp_raw_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
#if defined(__aarch64__)
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#else
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
#endif
}

/* 独立的 timespec，避免与 libc 声明冲突 */
struct rasp_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

/* statfs（内核 uapi 布局，避免与 bionic struct statfs 混用） */
struct rasp_statfs {
    long f_type;
    long f_bsize;
    long f_blocks;
    long f_bfree;
    long f_bavail;
    long f_files;
    long f_ffree;
    int32_t f_fsid[2];
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};

/* openat2 的 open_how 结构 */
struct rasp_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

#define RASP_ST_RDONLY 1
#define RASP_RESOLVE_NO_MAGICLINKS 0x02

/* getdents64 返回的记录布局 */
struct rasp_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/* ---------------- 语义化封装（失败返回 -1 并设置 errno） ---------------- */
int rasp_raw_open(const char *path, int flags, int mode);
int rasp_raw_openat(int dirfd, const char *path, int flags, int mode);
long rasp_raw_read(int fd, void *buf, size_t count);
int rasp_raw_close(int fd);
long rasp_raw_getdents64(int fd, void *buf, size_t count);
long rasp_raw_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz);
int rasp_raw_statx(int dirfd, const char *path, int flags, unsigned int mask, struct rasp_statx *stx);
int rasp_raw_pidfd_open(pid_t pid, unsigned int flags);
long rasp_raw_clone3(struct rasp_clone_args *args, size_t size);
long rasp_raw_clone(unsigned long flags, void *child_stack);
int rasp_raw_memfd_create(const char *name, unsigned int flags);
void *rasp_raw_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
long rasp_raw_wait4(pid_t pid, int *status, int options, void *rusage);
int rasp_raw_kill(pid_t pid, int sig);
void rasp_raw_exit_group(int code);
pid_t rasp_raw_getpid(void);
pid_t rasp_raw_gettid(void);
uid_t rasp_raw_getuid(void);
uid_t rasp_raw_geteuid(void);
long rasp_raw_clock_gettime(int clk, struct rasp_timespec *ts);
int rasp_raw_statfs(const char *path, struct rasp_statfs *out);
int rasp_raw_openat2(int dirfd, const char *path, struct rasp_open_how *how, size_t size);

/* 打开 pidfd 的只读目录句柄；不支持时返回 -1（调用方回退到 /proc/<pid> 路径） */
int rasp_pidfd_open_compat(pid_t pid);

#endif /* RASP_SYSCALL_H */
