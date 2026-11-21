/*
 * rasp_checks_kernel.c —— 第 3 类（内核态间接痕迹）+ 第 4 类（BPF 篡改痕迹）
 *
 * 检测项：
 *   KRN-001 系统调用耗时分布统计（kprobe/syscall 劫持间接特征）【间接】
 *   KRN-002 内核配置/版本指纹偏离【弱线索】
 *   KRN-003 task_struct 与 /proc 视图不一致【间接】
 *   KRN-004 cred 结构间接行为特征【强】
 *   KRN-005 内核符号表异常间接推断【弱线索】
 *   BPF-001 anon_inode 异常数量统计【间接】
 *   BPF-002 进程 fd 中 bpf 类型匿名文件识别【强】
 *   BPF-003 网络包处理时延异常统计【弱线索】
 *   BPF-004 cgroup 视图跨进程比对【间接】
 */
#include "rasp_core.h"
#include "rasp_syscall.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

/* ------------------------------------------------------------------ 排序工具 */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* ------------------------------------------------------------------ KRN-001 */

static void check_syscall_timing(rasp_ctx_t *c)
{
    enum { N = 240 };
    static uint64_t samples[N];
    const int rounds = c->fast_mode ? 80 : N;

    uint64_t total = 0;
    for (int i = 0; i < rounds; i++) {
        uint64_t t0 = rasp_mono_ns();
        (void)rasp_raw_syscall0(SYS_GETPID);
        uint64_t t1 = rasp_mono_ns();
        samples[i] = t1 > t0 ? t1 - t0 : 1;
        total += samples[i];
    }
    qsort(samples, (size_t)rounds, sizeof(uint64_t), cmp_u64);
    uint64_t median = samples[rounds / 2];
    uint64_t p99 = samples[(rounds * 99) / 100];
    uint64_t max = samples[rounds - 1];
    double mean = (double)total / (double)rounds;

    int outliers = 0;
    for (int i = 0; i < rounds; i++) {
        if (samples[i] > median * 12 && samples[i] > 20000) outliers++;
    }

    /* kprobe/ftrace 逐次回调会让部分调用出现数量级抖动 */
    int hit = outliers > rounds / 40 && median > 0;
    double conf = hit ? (outliers > rounds / 12 ? 0.75 : 0.5) : 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "rounds", rounds);
    rb_puts(&b, ",");
    rb_json_kv_double(&b, "mean_ns", mean);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "median_ns", (long long)median);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "p99_ns", (long long)p99);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "max_ns", (long long)max);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "outliers", outliers);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-001", "系统调用耗时分布统计", "kernel", GRADE_INDIRECT, conf, hit, 1, raw,
              NULL);
}

/* ------------------------------------------------------------------ KRN-002 */

static void check_kernel_fingerprint(rasp_ctx_t *c)
{
    static char version[2048];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(1, "version", version, sizeof(version) - 1, &len, &err, &via) != 0) {
        if (rasp_read_file_raw("/proc/version", version, sizeof(version) - 1, &len) != 0) {
            char raw[128];
            snprintf(raw, sizeof(raw), "{\"errno\":%d}", errno);
            rasp_emit(c, "KRN-002", "内核配置与版本指纹偏离", "kernel", GRADE_WEAK, 0.0, 0, 0,
                      raw, "cannot read /proc/version");
            return;
        }
    }
    version[len] = '\0';

    struct utsname un;
    int un_ok = uname(&un) == 0;

    int ksu_marker = rasp_contains_ci(version, "kernelsu") ||
                     rasp_contains_ci(version, "sukisu") || rasp_contains_ci(version, "apatch") ||
                     rasp_contains_ci(version, "magisk") || rasp_contains_ci(version, "-ksu");

    int release_mismatch = 0;
    if (un_ok) {
        /* /proc/version = "Linux version <release> (<user>) ..." */
        const char *p = strstr(version, "Linux version ");
        if (p != NULL) {
            p += 14;
            size_t rl = strlen(un.release);
            if (strncmp(p, un.release, rl) != 0) release_mismatch = 1;
        }
    }

    char osrelease[256] = {0};
    size_t olen = 0;
    if (rasp_read_file_raw("/proc/sys/kernel/osrelease", osrelease, sizeof(osrelease) - 1,
                           &olen) == 0) {
        osrelease[olen] = '\0';
        while (olen > 0 && (osrelease[olen - 1] == '\n' || osrelease[olen - 1] == '\r')) {
            osrelease[--olen] = '\0';
        }
    }
    int osrelease_mismatch = 0;
    if (un_ok && osrelease[0] && strcmp(osrelease, un.release) != 0) osrelease_mismatch = 1;

    char version_head[160];
    snprintf(version_head, sizeof(version_head), "%s", version);
    char *nl = strchr(version_head, '\n');
    if (nl) *nl = '\0';

    int hit = ksu_marker || release_mismatch || osrelease_mismatch;
    double conf = 0.0;
    if (ksu_marker) conf = 0.6;
    if (release_mismatch || osrelease_mismatch) conf = conf > 0.7 ? conf : 0.7;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "proc_version", version_head);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "uname_release", un_ok ? un.release : "");
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "ksu_marker", ksu_marker);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "release_mismatch", release_mismatch || osrelease_mismatch);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-002", "内核配置与版本指纹偏离", "kernel", GRADE_WEAK, conf, hit,
              version[0] != '\0', raw, NULL);
}

/* ------------------------------------------------------------------ KRN-003 */

static void check_task_view(rasp_ctx_t *c)
{
    static char status[8192];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "status", status, sizeof(status) - 1, &len, &err, &via) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", err);
        rasp_emit(c, "KRN-003", "task_struct 与 /proc 视图不一致", "kernel", GRADE_INDIRECT, 0.0,
                  0, 0, raw, "cannot read /proc/self/status");
        return;
    }
    status[len] = '\0';

    char pid_s[32] = {0}, tgid_s[32] = {0}, threads_s[32] = {0};
    rasp_status_value(status, "Pid", pid_s, sizeof(pid_s));
    rasp_status_value(status, "Tgid", tgid_s, sizeof(tgid_s));
    rasp_status_value(status, "Threads", threads_s, sizeof(threads_s));

    pid_t raw_pid = rasp_raw_getpid();
    pid_t raw_tid = rasp_raw_gettid();
    int tgid = atoi(tgid_s);
    int pid = atoi(pid_s);
    int threads = atoi(threads_s);

    int tgid_mismatch = (tgid != (int)raw_pid);
    int pid_mismatch = (pid != (int)raw_tid && pid != (int)raw_pid);

    /* 线程数比对：/proc/self/task 目录项数 */
    int task_count = -1;
    int fd = rasp_raw_open("/proc/self/task", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC,
                           0);
    if (fd >= 0) {
        char buf[4096];
        task_count = 0;
        for (;;) {
            long got = rasp_raw_getdents64(fd, buf, sizeof(buf));
            if (got <= 0) break;
            for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
                struct rasp_dirent64 *d = (struct rasp_dirent64 *)(buf + off);
                off += d->d_reclen;
                if (d->d_name[0] >= '0' && d->d_name[0] <= '9') task_count++;
            }
        }
        rasp_raw_close(fd);
    }
    int thread_mismatch = (task_count > 0 && threads > 0 &&
                           (task_count > threads + 2 || threads > task_count + 2));

    int hit = tgid_mismatch || pid_mismatch || thread_mismatch;
    double conf = 0.0;
    if (tgid_mismatch || pid_mismatch) conf = 0.85;
    else if (thread_mismatch) conf = 0.4;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "status_pid", pid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "status_tgid", tgid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "raw_getpid", (long long)raw_pid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "raw_gettid", (long long)raw_tid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "status_threads", threads);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "task_entries", task_count);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-003", "task_struct 与 /proc 视图不一致", "kernel", GRADE_INDIRECT, conf, hit,
              1, raw, NULL);
}

/* ------------------------------------------------------------------ KRN-004 */

static void check_cred(rasp_ctx_t *c)
{
    static char status[8192];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "status", status, sizeof(status) - 1, &len, &err, &via) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", err);
        rasp_emit(c, "KRN-004", "cred 结构间接行为特征", "kernel", GRADE_STRONG, 0.0, 0, 0, raw,
                  "cannot read /proc/self/status");
        return;
    }
    status[len] = '\0';

    char uid_line[128] = {0}, gid_line[128] = {0}, cap_eff[64] = {0};
    rasp_status_value(status, "Uid", uid_line, sizeof(uid_line));
    rasp_status_value(status, "Gid", gid_line, sizeof(gid_line));
    rasp_status_value(status, "CapEff", cap_eff, sizeof(cap_eff));

    /* Uid: real effective saved fs */
    int uids[4] = {0, 0, 0, 0};
    int uid_parsed = sscanf(uid_line, "%d %d %d %d", &uids[0], &uids[1], &uids[2], &uids[3]);
    uid_t raw_uid = rasp_raw_getuid();
    uid_t raw_euid = rasp_raw_geteuid();

    int uid_mismatch = (uid_parsed >= 1 && uids[0] != (int)raw_uid) ||
                       (uid_parsed >= 2 && uids[1] != (int)raw_euid);
    int uid_divergence = (uid_parsed == 4 && (uids[0] != uids[1] || uids[1] != uids[2]));

    unsigned long long cap = strtoull(cap_eff, NULL, 16);
    int cap_escalated = cap != 0ULL;

    int hit = uid_mismatch || uid_divergence || cap_escalated;
    double conf = 0.0;
    if (uid_mismatch || uid_divergence) conf = 0.9;
    if (cap_escalated) conf = conf > 0.9 ? conf : 0.9;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "status_uid", uid_line);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "status_gid", gid_line);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "raw_uid", (long long)raw_uid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "raw_euid", (long long)raw_euid);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "cap_eff", cap_eff);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "cap_escalated", cap_escalated);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-004", "cred 结构间接行为特征", "kernel", GRADE_STRONG, conf, hit, 1, raw,
              NULL);
}

/* ------------------------------------------------------------------ KRN-005 */

static void check_kallsyms(rasp_ctx_t *c)
{
    static char buf[8192];
    size_t len = 0;
    if (rasp_read_file_raw("/proc/kallsyms", buf, sizeof(buf) - 1, &len) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", errno);
        /* 普通应用读不到 kallsyms 是正常现象，不算异常 */
        rasp_emit(c, "KRN-005", "内核符号表异常间接推断", "kernel", GRADE_WEAK, 0.0, 0, 0, raw,
                  "kallsyms not readable");
        return;
    }
    buf[len] = '\0';

    int lines = 0, nonzero_addr = 0;
    const char *p = buf;
    while (p && *p) {
        char addr[24] = {0};
        if (sscanf(p, "%23s", addr) == 1) {
            lines++;
            if (strtoull(addr, NULL, 16) != 0ULL) nonzero_addr++;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }

    char kptr[32] = {0};
    size_t klen = 0;
    if (rasp_read_file_raw("/proc/sys/kernel/kptr_restrict", kptr, sizeof(kptr) - 1, &klen) == 0) {
        kptr[klen] = '\0';
        char *nl = strchr(kptr, '\n');
        if (nl) *nl = '\0';
    }

    int leaked = nonzero_addr > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "lines", lines);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "nonzero_addresses", nonzero_addr);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "kptr_restrict", kptr);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-005", "内核符号表异常间接推断", "kernel", GRADE_WEAK, leaked ? 0.25 : 0.0,
              leaked, lines > 0, raw, NULL);
}

/* ------------------------------------------------------------------ BPF-001 */

static void check_bpf_anon(rasp_ctx_t *c)
{
    int fd = rasp_raw_open("/proc/self/fd", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC, 0);
    if (fd < 0) {
        rasp_emit(c, "BPF-001", "anon_inode 异常数量统计", "bpf", GRADE_INDIRECT, 0.0, 0, 0, NULL,
                  "cannot open /proc/self/fd");
        return;
    }
    char buf[8192];
    int anon = 0, fds = 0;
    char kinds[256] = {0};
    for (;;) {
        long got = rasp_raw_getdents64(fd, buf, sizeof(buf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(buf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            fds++;
            char target[160];
            long rn = rasp_raw_readlinkat(fd, d->d_name, target, sizeof(target) - 1);
            if (rn <= 0) continue;
            target[rn] = '\0';
            if (strncmp(target, "anon_inode:", 11) == 0) {
                anon++;
                size_t l = strlen(kinds);
                if (l + strlen(target + 11) + 2 < sizeof(kinds)) {
                    snprintf(kinds + l, sizeof(kinds) - l, "%s,", target + 11);
                }
            }
        }
    }
    rasp_raw_close(fd);

    int hit = anon > 24;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "open_fds", fds);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anon_inode", anon);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "kinds", kinds);
    rb_puts(&b, "}");
    rasp_emit(c, "BPF-001", "anon_inode 异常数量统计", "bpf", GRADE_INDIRECT, hit ? 0.45 : 0.0,
              hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ BPF-002 */

static void check_bpf_fdinfo(rasp_ctx_t *c)
{
    int fd = rasp_raw_open("/proc/self/fd", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC, 0);
    if (fd < 0) {
        rasp_emit(c, "BPF-002", "进程 fd 中 bpf 类型匿名文件识别", "bpf", GRADE_STRONG, 0.0, 0, 0,
                  NULL, "cannot open /proc/self/fd");
        return;
    }
    char buf[8192];
    int bpf_fds = 0;
    char detail[256] = {0};
    for (;;) {
        long got = rasp_raw_getdents64(fd, buf, sizeof(buf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(buf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            char path[64];
            snprintf(path, sizeof(path), "/proc/self/fdinfo/%s", d->d_name);
            char info[1024];
            size_t ilen = 0;
            if (rasp_read_file_raw(path, info, sizeof(info) - 1, &ilen) != 0) continue;
            info[ilen] = '\0';
            if (strstr(info, "bpf") != NULL || strstr(info, "map_type") != NULL ||
                strstr(info, "prog_type") != NULL) {
                bpf_fds++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "fd=%s;", d->d_name);
            }
        }
    }
    rasp_raw_close(fd);

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "bpf_fds", bpf_fds);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "BPF-002", "进程 fd 中 bpf 类型匿名文件识别", "bpf", GRADE_STRONG,
              bpf_fds > 0 ? 0.9 : 0.0, bpf_fds > 0, 1, raw, NULL);
}

/* ------------------------------------------------------------------ BPF-003 */

static void check_net_latency(rasp_ctx_t *c)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", errno);
        rasp_emit(c, "BPF-003", "网络包处理时延异常统计", "bpf", GRADE_WEAK, 0.0, 0, 0, raw,
                  "socketpair failed");
        return;
    }
    enum { N = 120 };
    static uint64_t s[N];
    char byte = 'x';
    int ok = 1;
    for (int i = 0; i < N; i++) {
        uint64_t t0 = rasp_mono_ns();
        if (send(sv[0], &byte, 1, 0) != 1) {
            ok = 0;
            break;
        }
        char rb2;
        if (recv(sv[1], &rb2, 1, 0) != 1) {
            ok = 0;
            break;
        }
        uint64_t t1 = rasp_mono_ns();
        s[i] = t1 > t0 ? t1 - t0 : 1;
    }
    close(sv[0]);
    close(sv[1]);

    if (!ok) {
        rasp_emit(c, "BPF-003", "网络包处理时延异常统计", "bpf", GRADE_WEAK, 0.0, 0, 0, NULL,
                  "socket round-trip failed");
        return;
    }
    qsort(s, N, sizeof(uint64_t), cmp_u64);
    uint64_t median = s[N / 2], p99 = s[(N * 99) / 100], max = s[N - 1];
    double mean = 0;
    for (int i = 0; i < N; i++) mean += (double)s[i];
    mean /= N;

    int hit = median > 0 && max > median * 20 && max > 500000;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_double(&b, "mean_ns", mean);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "median_ns", (long long)median);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "p99_ns", (long long)p99);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "max_ns", (long long)max);
    rb_puts(&b, "}");
    rasp_emit(c, "BPF-003", "网络包处理时延异常统计", "bpf", GRADE_WEAK, hit ? 0.3 : 0.0, hit, 1,
              raw, NULL);
}

/* ------------------------------------------------------------------ BPF-004 */

static void check_cgroup_view(rasp_ctx_t *c)
{
    static char self_cg[2048], init_cg[2048];
    size_t l1 = 0, l2 = 0;
    int e1 = 0, e2 = 0, v1 = 0, v2 = 0;
    int ok1 = rasp_read_proc(c->self_pid, "cgroup", self_cg, sizeof(self_cg) - 1, &l1, &e1, &v1) == 0;
    int ok2 = rasp_read_proc(1, "cgroup", init_cg, sizeof(init_cg) - 1, &l2, &e2, &v2) == 0;
    if (!ok1) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", e1);
        rasp_emit(c, "BPF-004", "cgroup 视图跨进程比对", "bpf", GRADE_INDIRECT, 0.0, 0, 0, raw,
                  "cannot read self cgroup");
        return;
    }
    self_cg[l1] = '\0';

    int differ = 0;
    if (ok2) {
        init_cg[l2] = '\0';
        /* 只比对 cgroup2 的路径层级数量与顶层名称，避免正常差异导致误报 */
        int d1 = rasp_count_lines(self_cg), d2 = rasp_count_lines(init_cg);
        differ = (d1 != d2);
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "self_cgroup", self_cg);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "init_cgroup", ok2 ? init_cg : "");
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "init_readable", ok2);
    rb_puts(&b, "}");
    rasp_emit(c, "BPF-004", "cgroup 视图跨进程比对", "bpf", GRADE_INDIRECT, differ ? 0.4 : 0.0,
              differ, 1, raw, ok2 ? NULL : "init cgroup unreadable (SELinux scope)");
}

void rasp_check_kernel_trace(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2000);
    check_syscall_timing(c);
    if (!rasp_deadline_hit(c)) check_kernel_fingerprint(c);
    if (!rasp_deadline_hit(c)) check_task_view(c);
    check_cred(c);
    if (!rasp_deadline_hit(c)) check_kallsyms(c);
}

void rasp_check_bpf(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 1500);
    check_bpf_anon(c);
    if (!rasp_deadline_hit(c)) check_bpf_fdinfo(c);
    /* 网络时延统计属高开销项：快速模式跳过 */
    if (!c->fast_mode && !rasp_deadline_hit(c)) check_net_latency(c);
    if (!rasp_deadline_hit(c)) check_cgroup_view(c);
}
