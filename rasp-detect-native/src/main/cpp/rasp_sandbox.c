/*
 * rasp_sandbox.c —— 干净检测沙箱（clone3）+ 沙箱视图一致性
 *
 * 检测项：
 *   MNT-007 沙箱子进程视图一致性【强】
 *   SBX-001 clone3 沙箱独立性校验【间接】
 *
 * 原理：通过 clone3 创建无 Java 运行时、无第三方 so 的新进程（fork 语义、
 *       不共享地址空间），在子进程内用直调 syscall 重新读取挂载视图与文件元信息。
 *       父进程的 /proc 视图若被用户态 Hook 伪造，父子结果必然不一致。
 * 约束：不调用 setns（需要 CAP_SYS_ADMIN），子进程天然继承同一 mount namespace。
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    volatile int ready;
    int child_pid;
    int parent_pid;
    int uid;
    int mount_entries;
    uint64_t mountinfo_hash;
    uint64_t app_process_ino;
    int64_t app_process_size;
    int read_errno;
    char error[96];
} sandbox_shm_t;

static sandbox_shm_t *g_shm;

static pid_t rasp_getppid_raw(void);

/*
 * 子进程侧逻辑：只用直调 syscall + 栈/静态缓冲，不调用 malloc、不加锁、
 * 不触碰 Java 运行时，避免 fork 后锁状态不一致。
 */
static void sandbox_child_main(void)
{
    sandbox_shm_t *shm = g_shm;
    if (shm == NULL) rasp_raw_exit_group(1);

    shm->child_pid = (int)rasp_raw_getpid();
    shm->parent_pid = (int)rasp_getppid_raw();

    static char buf[64 * 1024];
    int fd = rasp_raw_open("/proc/self/mountinfo", RASP_O_RDONLY | RASP_O_CLOEXEC, 0);
    if (fd < 0) {
        shm->read_errno = errno;
        shm->ready = 1;
        rasp_raw_exit_group(0);
    }
    size_t total = 0;
    for (;;) {
        long n = rasp_raw_read(fd, buf + total, sizeof(buf) - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            shm->read_errno = errno;
            break;
        }
        if (n == 0) break;
        total += (size_t)n;
        if (total + 1 >= sizeof(buf)) break;
    }
    rasp_raw_close(fd);
    buf[total] = '\0';

    int lines = 0;
    for (size_t i = 0; i < total; i++) {
        if (buf[i] == '\n') lines++;
    }
    shm->mount_entries = lines;
    shm->mountinfo_hash = rasp_hash64(buf, total);
    shm->uid = (int)rasp_raw_getuid();

    struct rasp_statx stx;
    memset(&stx, 0, sizeof(stx));
    if (rasp_raw_statx(RASP_AT_FDCWD, "/system/bin/app_process64", 0, RASP_STATX_BASIC_STATS,
                       &stx) == 0) {
        shm->app_process_ino = stx.stx_ino;
        shm->app_process_size = (int64_t)stx.stx_size;
    }
    shm->ready = 1;
    rasp_raw_exit_group(0);
}

static int sandbox_spawn(sandbox_shm_t *shm, pid_t *out_pid)
{
    struct rasp_clone_args args;
    memset(&args, 0, sizeof(args));
    args.exit_signal = RASP_SIGCHLD;

    long pid = -1;
    /* clone3 先由兼容性探测确认可用，避免 seccomp TRAP 直接把主进程带走 */
    if (rasp_clone3_enabled()) {
        pid = rasp_raw_clone3(&args, sizeof(args));
    }
    if (pid < 0) {
        /* 回退到 clone(SIGCHLD)：语义等价（fork），所有 Android 内核都允许 */
        pid = rasp_raw_clone((unsigned long)RASP_SIGCHLD, NULL);
    }
    if (pid < 0) return -1;

    if (pid == 0) {
        sandbox_child_main();
        rasp_raw_exit_group(0); /* 不可达 */
    }
    *out_pid = (pid_t)pid;
    return 0;
}

static void nanosleep_ms(long ms)
{
    struct rasp_timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    /* clock_nanosleep(clockid, flags, req, rem) —— 必须是四参数，否则会立即返回造成忙等 */
    (void)rasp_raw_syscall4(SYS_CLOCK_NANOSLEEP, RASP_CLOCK_MONOTONIC, 0, (long)&ts, 0);
}

/* 子进程侧读取父 pid：直接解析 /proc/self/status，避免在 fork 后使用 libc 缓存 */
static pid_t rasp_getppid_raw(void)
{
    static char st[2048];
    size_t len = 0;
    if (rasp_read_file_raw("/proc/self/status", st, sizeof(st) - 1, &len) != 0) return -1;
    st[len] = '\0';
    char buf[32] = {0};
    if (rasp_status_value(st, "PPid", buf, sizeof(buf)) != 0) return -1;
    return (pid_t)atoi(buf);
}

void rasp_check_sandbox(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2500);

    /* 父进程基线视图 */
    static char pbuf[64 * 1024];
    size_t plen = 0;
    uint64_t phash = 0;
    int pentries = 0;
    int p_ok = rasp_read_file_raw("/proc/self/mountinfo", pbuf, sizeof(pbuf) - 1, &plen) == 0;
    if (p_ok) {
        pbuf[plen] = '\0';
        phash = rasp_hash64(pbuf, plen);
        pentries = rasp_count_lines(pbuf);
    }

    struct rasp_statx pstx;
    memset(&pstx, 0, sizeof(pstx));
    int pstat_ok = rasp_raw_statx(RASP_AT_FDCWD, "/system/bin/app_process64", 0,
                                  RASP_STATX_BASIC_STATS, &pstx) == 0;

    if (c->shm == NULL || c->shm_size < sizeof(sandbox_shm_t)) {
        void *mem = rasp_raw_mmap(NULL, sizeof(sandbox_shm_t), 3 /* PROT_READ|PROT_WRITE */,
                                  RASP_MAP_SHARED | RASP_MAP_ANONYMOUS, -1, 0);
        if (mem == (void *)-1 || mem == NULL) {
            rasp_emit(c, "SBX-001", "clone3 沙箱独立性校验", "sandbox", GRADE_INDIRECT, 0.0, 0, 0,
                      NULL, "cannot allocate shared memory");
            return;
        }
        c->shm = mem;
        c->shm_size = sizeof(sandbox_shm_t);
        c->shm_ready = 1;
    }
    sandbox_shm_t *shm = (sandbox_shm_t *)c->shm;
    memset(shm, 0, sizeof(*shm));
    shm->parent_pid = (int)c->self_pid;
    g_shm = shm;

    pid_t child = -1;
    if (sandbox_spawn(shm, &child) != 0) {
        char err[128];
        snprintf(err, sizeof(err), "clone3/clone failed: errno=%d (%s)", errno, strerror(errno));
        rasp_emit(c, "SBX-001", "clone3 沙箱独立性校验", "sandbox", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, err);
        rasp_emit(c, "MNT-007", "沙箱子进程视图一致性", "sandbox", GRADE_STRONG, 0.0, 0, 0, NULL,
                  err);
        rasp_raw_munmap(shm, sizeof(sandbox_shm_t));
        g_shm = NULL;
        c->shm = NULL;
        c->shm_size = 0;
        c->shm_ready = 0;
        return;
    }

    /* 等待子进程完成，最长 1500ms，超时即熔断并回收 */
    int status = 0;
    int waited = 0;
    while (waited < 1500) {
        long r = rasp_raw_wait4(child, &status, 1 /* WNOHANG */, NULL);
        if (r == child) break;
        nanosleep_ms(2);
        waited += 2;
        __sync_synchronize(); /* 子进程写 ready 前已写入其余字段 */
        if (shm->ready) {
            (void)rasp_raw_wait4(child, &status, 1, NULL);
            break;
        }
    }
    int timed_out = (waited >= 1500);
    if (timed_out) {
        (void)rasp_raw_kill(child, RASP_SIGKILL);
        (void)rasp_raw_wait4(child, &status, 0, NULL);
    }

    int child_ok = shm->ready && shm->read_errno == 0 && !timed_out;
    int view_equal = child_ok && phash == shm->mountinfo_hash;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "child_pid", (int)child);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "parent_pid", (int)c->self_pid);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "child_ready", shm->ready);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "parent_entries", pentries);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "child_entries", shm->mount_entries);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "hash_equal", view_equal);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "parent_hash_lo", (long long)(phash & 0x7fffffffULL));
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "child_hash_lo", (long long)(shm->mountinfo_hash & 0x7fffffffULL));
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "timed_out_ms", timed_out ? 1500 : waited);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "read_errno", shm->read_errno);
    rb_puts(&b, "}");

    /* 父子视图必须完全一致；不一致说明挂载视图被 Hook 伪造 */
    int view_hit = child_ok && !view_equal;
    rasp_emit(c, "MNT-007", "沙箱子进程视图一致性", "sandbox", GRADE_STRONG,
              view_hit ? 0.9 : 0.0, view_hit, child_ok, raw,
              child_ok ? NULL : (timed_out ? "sandbox timeout" : "sandbox failed"));

    /* 沙箱独立性：子进程必须是真实新进程、且回报的父 pid 指向本进程 */
    int independent = (child_ok && shm->child_pid == (int)child &&
                       shm->parent_pid == (int)c->self_pid)
                          ? 1
                          : 0;
    rasp_buf_t b2;
    char raw2[RASP_RAW_MAX];
    rb_init(&b2, raw2, sizeof(raw2));
    rb_puts(&b2, "{");
    rb_json_kv_int(&b2, "spawned_pid", (int)child);
    rb_puts(&b2, ",");
    rb_json_kv_int(&b2, "child_reported_pid", shm->child_pid);
    rb_puts(&b2, ",");
    rb_json_kv_int(&b2, "child_reported_ppid", shm->parent_pid);
    rb_puts(&b2, ",");
    rb_json_kv_bool(&b2, "independent", independent);
    rb_puts(&b2, ",");
    rb_json_kv_bool(&b2, "stat_available", pstat_ok);
    rb_puts(&b2, "}");
    rasp_emit(c, "SBX-001", "clone3 沙箱独立性校验", "sandbox", GRADE_INDIRECT,
              (child_ok && !independent) ? 0.5 : 0.0, child_ok && !independent, child_ok, raw2,
              child_ok ? NULL : "sandbox not available");

    /* 共享页收尾：本函数每轮只调用一次，1.0.3 及更早版本未 munmap（每轮泄漏一页） */
    rasp_raw_munmap(shm, sizeof(sandbox_shm_t));
    g_shm = NULL;
    c->shm = NULL;
    c->shm_size = 0;
    c->shm_ready = 0;
}
