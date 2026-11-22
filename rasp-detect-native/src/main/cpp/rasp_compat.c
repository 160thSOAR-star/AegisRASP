/*
 * rasp_compat.c —— 兼容性探测与阶段埋点
 *
 * 背景：部分 ROM / 内核的 seccomp 策略会对少数较新的系统调用直接返回
 * SECCOMP_RET_TRAP（进程收到 SIGSYS 并终止），而不是 ENOSYS/EPERM。
 * 由于 SIGSYS 无法在进程内安全恢复，本模块把「是否允许调用 pidfd_open / openat2」
 * 交给一个**一次性子进程**去探测：
 *
 *   - 子进程正常完成 => 记录两个调用是否可用，父进程据此决定是否启用；
 *   - 子进程被信号杀死 => 父进程拿到 WTERMSIG，永久禁用对应调用（本次会话）。
 *
 * 这样即使某个系统调用会触发致命信号，死的也只是探测子进程，主进程与 UI 不受影响。
 *
 * 另提供阶段埋点：每个检测模块执行前把阶段名写入 <files>/last_stage，
 * 若发生 native 崩溃，下次启动可据此定位崩溃发生在哪个模块。
 */
#include "rasp_core.h"
#include "rasp_syscall.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_pidfd_ok = 0;
static int g_openat2_ok = 0;
static int g_clone3_ok = 0;

int rasp_pidfd_enabled(void)
{
    return g_pidfd_ok;
}

int rasp_openat2_enabled(void)
{
    return g_openat2_ok;
}

int rasp_clone3_enabled(void)
{
    return g_clone3_ok;
}

typedef struct {
    volatile int ready;
    int pidfd_ok;
    int openat2_ok;
    int statfs_ok;
    int clone3_ok;
} compat_shm_t;

static compat_shm_t *g_probe_shm;

static void sleep_ms(long ms)
{
    struct rasp_timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    /* clock_nanosleep(clockid, flags, req, rem)：四参数，之前少传两个参数会导致忙等 */
    (void)rasp_raw_syscall4(SYS_CLOCK_NANOSLEEP, RASP_CLOCK_MONOTONIC, 0, (long)&ts, 0);
}

/* 子进程：只做系统调用探测，不调用 malloc / 不加锁 / 不碰 Java */
static void probe_child_main(void)
{
    compat_shm_t *s = g_probe_shm;
    if (s == NULL) rasp_raw_exit_group(2);

    int fd = rasp_raw_pidfd_open(rasp_raw_getpid(), 0);
    s->pidfd_ok = fd >= 0 ? 1 : 0;
    if (fd >= 0) rasp_raw_close(fd);

    struct rasp_open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = RASP_O_RDONLY | RASP_O_CLOEXEC;
    how.resolve = 0;
    int fd2 = rasp_raw_openat2(RASP_AT_FDCWD, "/proc/version", &how, sizeof(how));
    s->openat2_ok = fd2 >= 0 ? 1 : 0;
    if (fd2 >= 0) rasp_raw_close(fd2);

    struct rasp_statfs sf;
    memset(&sf, 0, sizeof(sf));
    s->statfs_ok = rasp_raw_statfs("/system", &sf) == 0 ? 1 : 0;

    /*
     * clone3 用「非法参数」探测：size=0 时内核在拷贝参数前就返回 EINVAL，
     * 不会真的创建进程；若该 ROM 的 seccomp 对 clone3 返回 TRAP，死的是探测子进程。
     */
    errno = 0;
    long c3 = rasp_raw_clone3(NULL, 0);
    s->clone3_ok = (c3 < 0 && errno == EINVAL) ? 1 : 0;

    s->ready = 1;
    rasp_raw_exit_group(0);}

static void write_probe_report(rasp_ctx_t *c)
{
    if (c == NULL || c->stage_dir[0] == '\0') return;
    char path[320];
    snprintf(path, sizeof(path), "%s/compat_probe.txt", c->stage_dir);

    char buf[192];
    snprintf(buf, sizeof(buf), "pidfd=%d openat2=%d clone3=%d sig=%d\n", g_pidfd_ok,
             g_openat2_ok, g_clone3_ok, c->probe_killed_sig);
    int fd = rasp_raw_open(path, RASP_O_WRONLY | RASP_O_CREAT | RASP_O_TRUNC | RASP_O_CLOEXEC, 0600);
    if (fd < 0) return;
    (void)rasp_raw_write(fd, buf, strlen(buf));
    rasp_raw_close(fd);
}

/*
 * 探测入口：必须在任何可能使用 pidfd_open / openat2 的检测之前调用。
 * 失败或超时时保持"全部禁用"，即退化为纯 /proc 路径 + 跳过 openat2 比对。
 */
void rasp_probe_compat(rasp_ctx_t *c)
{
    if (c == NULL) return;
    g_pidfd_ok = 0;
    g_openat2_ok = 0;
    g_clone3_ok = 0;
    c->probe_killed_sig = 0;
    c->pidfd_allowed = 0;
    c->openat2_allowed = 0;

    void *mem = rasp_raw_mmap(NULL, sizeof(compat_shm_t), 3 /* RW */,
                              RASP_MAP_SHARED | RASP_MAP_ANONYMOUS, -1, 0);
    if (mem == (void *)-1 || mem == NULL) {
        write_probe_report(c);
        return;
    }
    memset(mem, 0, sizeof(compat_shm_t));
    g_probe_shm = (compat_shm_t *)mem;

    /* 用 clone(SIGCHLD) 而不是 clone3 创建探测子进程，避免依赖待验证的 clone3 */
    pid_t pid = (pid_t)rasp_raw_clone((unsigned long)RASP_SIGCHLD, NULL);
    if (pid < 0) {
        write_probe_report(c);
        rasp_raw_munmap(mem, sizeof(compat_shm_t));
        g_probe_shm = NULL;
        return;
    }
    if (pid == 0) {
        probe_child_main();
        rasp_raw_exit_group(3); /* 不可达 */
    }

    int status = 0;
    int finished = 0;
    for (int i = 0; i < 400; i++) { /* 最多约 800ms */
        long r = rasp_raw_wait4(pid, &status, 1 /* WNOHANG */, NULL);
        if (r == pid) {
            finished = 1;
            break;
        }
        __sync_synchronize(); /* 子进程写 ready 之前已写入其余字段，这里建立跨进程可见性 */
        if (g_probe_shm->ready) {
            (void)rasp_raw_wait4(pid, &status, 0, NULL);
            finished = 1;
            break;
        }
        sleep_ms(2);
    }
    if (!finished) {
        (void)rasp_raw_kill(pid, RASP_SIGKILL);
        (void)rasp_raw_wait4(pid, &status, 0, NULL);
    }

    if (WIFSIGNALED(status)) {
        /* 子进程被致命信号终止：说明该 ROM 的 seccomp 会 TRAP 这些调用，全部禁用 */
        c->probe_killed_sig = WTERMSIG(status);
    } else if (g_probe_shm->ready) {
        g_pidfd_ok = g_probe_shm->pidfd_ok;
        g_openat2_ok = g_probe_shm->openat2_ok;
        g_clone3_ok = g_probe_shm->clone3_ok;
    }
    c->pidfd_allowed = g_pidfd_ok;
    c->openat2_allowed = g_openat2_ok;

    write_probe_report(c);

    /* MAP_SHARED 匿名页必须收尾：1.0.3 及更早版本每轮检测泄漏一页（未 munmap） */
    rasp_raw_munmap(mem, sizeof(compat_shm_t));
    g_probe_shm = NULL;
}

/* 阶段埋点：崩溃后下次启动可读到最后执行到的模块 */
void rasp_stage(rasp_ctx_t *c, const char *stage)
{
    if (c == NULL || stage == NULL || c->stage_dir[0] == '\0') return;
    char path[320];
    snprintf(path, sizeof(path), "%s/last_stage", c->stage_dir);
    int fd = rasp_raw_open(path, RASP_O_WRONLY | RASP_O_CREAT | RASP_O_TRUNC | RASP_O_CLOEXEC, 0600);
    if (fd < 0) return;
    (void)rasp_raw_write(fd, stage, strlen(stage));
    rasp_raw_close(fd);
}
