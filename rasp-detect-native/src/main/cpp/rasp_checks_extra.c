/*
 * rasp_checks_extra.c —— 1.0.1 新增检测项（此前未覆盖的观测面）
 *
 * 设计思路：这些项不再依赖"名字/路径黑名单"，而是寻找**两类新的物理矛盾**：
 *   A. 内核不同接口对同一事实的说法不一致（statfs vs mountinfo、statx dev vs mountinfo dev、
 *      btime vs boottime vs uptime、openat2 vs openat、readdir vs 直接路径访问）；
 *   B. 本应存在的用户态/内核结构缺失或错位（errno 语义、非系统代码映射、函数地址权限、
 *      异常线程名）。
 *
 * 检测项：
 *   MNT-008 挂载只读标志与 statfs 一致性【间接】
 *   MNT-009 挂载设备号与 statx 设备号一致性【间接】
 *   KRN-006 内核时序自洽性（btime / uptime / CLOCK_BOOTTIME）【间接】
 *   KRN-007 syscall 返回码语义异常探针【间接】
 *   INJ-005 非系统代码映射来源检测【间接】
 *   AHK-005 函数地址与可执行段一致性【强】
 *   AHK-006 openat2 与 openat 双路径一致性【强】
 *   FOPS-001 目录枚举与直接访问不一致（procfs 目录过滤）【强】
 *   ZYS-007 异常线程名与线程注入痕迹【弱】
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

/* ------------------------------------------------------------------ 环境判定 */

/*
 * 模拟器/虚拟化环境判定：Android Studio 模拟器的 /proc 视图与代码映射来源
 * 与真机差异较大（inject / fds / 映射路径），相关项在模拟器上应标记为不可用，
 * 而不是给出误报。结果做进程内缓存（属性不会在运行期变化）。
 */
static int running_on_emulator(void)
{
    static int cached = -1;
    if (cached >= 0) return cached;

    char v[PROP_VALUE_MAX];
    memset(v, 0, sizeof(v));
    __system_property_get("ro.kernel.qemu", v);
    if (v[0] == '1') return (cached = 1);

    memset(v, 0, sizeof(v));
    __system_property_get("ro.boot.qemu", v);
    if (v[0] == '1') return (cached = 1);

    memset(v, 0, sizeof(v));
    __system_property_get("ro.hardware", v);
    if (strcmp(v, "ranchu") == 0 || strcmp(v, "goldfish") == 0) return (cached = 1);

    return (cached = 0);
}

/* ------------------------------------------------------------------ 通用解析 */

typedef struct {
    int found;
    char opts[256];
    uint64_t dev_major;
    uint64_t dev_minor;
} mount_entry_t;

/* 在 mountinfo 文本中查找挂载点完全等于 path 的条目 */
static void mountinfo_lookup(const char *buf, const char *path, mount_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    if (buf == NULL || path == NULL) return;

    char *copy = strdup(buf);
    if (copy == NULL) return;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        char point[256];
        if (rasp_field(line, 4, point, sizeof(point)) != 0) continue;
        if (strcmp(point, path) != 0) continue;

        char dev[64];
        snprintf(out->opts, sizeof(out->opts), "%s", "");
        rasp_field(line, 5, out->opts, sizeof(out->opts));
        if (rasp_field(line, 2, dev, sizeof(dev)) == 0) {
            char *colon = strchr(dev, ':');
            if (colon) {
                *colon = '\0';
                out->dev_major = strtoull(dev, NULL, 10);
                out->dev_minor = strtoull(colon + 1, NULL, 10);
            }
        }
        out->found = 1;
        break;
    }
    free(copy);
}

static int opts_is_readonly(const char *opts)
{
    if (opts == NULL || opts[0] == '\0') return -1;
    /* mountinfo 第 6 字段形如 rw,nosuid,relatime 或 ro,seclabel */
    if (strncmp(opts, "ro", 2) == 0 && (opts[2] == ',' || opts[2] == '\0')) return 1;
    if (strncmp(opts, "rw", 2) == 0 && (opts[2] == ',' || opts[2] == '\0')) return 0;
    return -1;
}

static int read_self_mountinfo(char *buf, size_t cap)
{
    size_t len = 0;
    if (rasp_read_file_raw("/proc/self/mountinfo", buf, cap - 1, &len) != 0) return -1;
    buf[len] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ MNT-008 */

static void check_statfs_flags(rasp_ctx_t *c)
{
    static char mi[96 * 1024];
    if (read_self_mountinfo(mi, sizeof(mi)) != 0) {
        rasp_emit(c, "MNT-008", "挂载只读标志与 statfs 一致性", "mount", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "cannot read mountinfo");
        return;
    }

    static const char *const paths[] = {"/system", "/vendor", "/product", "/system_ext"};
    int checked = 0, mismatch = 0;
    char detail[384] = {0};

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        mount_entry_t me;
        mountinfo_lookup(mi, paths[i], &me);
        if (!me.found) continue;
        int expect_ro = opts_is_readonly(me.opts);
        if (expect_ro < 0) continue;

        struct rasp_statfs sf;
        memset(&sf, 0, sizeof(sf));
        if (rasp_raw_statfs(paths[i], &sf) != 0) continue;
        checked++;

        int actual_ro = (sf.f_flags & RASP_ST_RDONLY) != 0;
        if (actual_ro != expect_ro) {
            mismatch++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(mount=%s,statfs=%s);", paths[i],
                     expect_ro ? "ro" : "rw", actual_ro ? "ro" : "rw");
        }
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mismatched", mismatch);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "MNT-008", "挂载只读标志与 statfs 一致性", "mount", GRADE_INDIRECT,
              mismatch > 0 ? 0.6 : 0.0, mismatch > 0, checked > 0, raw,
              checked > 0 ? NULL : "no mount point available for statfs");
}

/* ------------------------------------------------------------------ MNT-009 */

static void check_mount_dev(rasp_ctx_t *c)
{
    static char mi[96 * 1024];
    if (read_self_mountinfo(mi, sizeof(mi)) != 0) {
        rasp_emit(c, "MNT-009", "挂载设备号与 statx 设备号一致性", "mount", GRADE_INDIRECT, 0.0,
                  0, 0, NULL, "cannot read mountinfo");
        return;
    }

    static const struct {
        const char *path;
        const char *mount_point;
    } probes[] = {
        {"/system/bin/app_process64", "/system"},
        {"/system/build.prop", "/system"},
        {"/product/build.prop", "/product"},
    };

    int checked = 0, mismatch = 0;
    char detail[384] = {0};

    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        struct rasp_statx stx;
        memset(&stx, 0, sizeof(stx));
        if (rasp_raw_statx(RASP_AT_FDCWD, probes[i].path, 0, RASP_STATX_BASIC_STATS, &stx) != 0) {
            continue;
        }
        mount_entry_t me;
        mountinfo_lookup(mi, probes[i].mount_point, &me);
        if (!me.found) continue;
        checked++;
        /* 覆盖式挂载/命名空间切换会让"文件所在设备"与"挂载表登记的设备"脱节 */
        if (stx.stx_dev_major != me.dev_major || stx.stx_dev_minor != me.dev_minor) {
            mismatch++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(statx=%u:%u,mount=%llu:%llu);",
                     probes[i].path, stx.stx_dev_major, stx.stx_dev_minor,
                     (unsigned long long)me.dev_major, (unsigned long long)me.dev_minor);
        }
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mismatched", mismatch);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "MNT-009", "挂载设备号与 statx 设备号一致性", "mount", GRADE_INDIRECT,
              mismatch > 0 ? 0.65 : 0.0, mismatch > 0, checked > 0, raw,
              checked > 0 ? NULL : "no comparable device number");
}

/* ------------------------------------------------------------------ KRN-006 */

static void check_time_sanity(rasp_ctx_t *c)
{
    static char statbuf[8192];
    size_t len = 0;
    if (rasp_read_file_raw("/proc/stat", statbuf, sizeof(statbuf) - 1, &len) != 0) {
        rasp_emit(c, "KRN-006", "内核时序自洽性（btime / uptime / BOOTTIME）", "kernel",
                  GRADE_INDIRECT, 0.0, 0, 0, NULL, "cannot read /proc/stat");
        return;
    }
    statbuf[len] = '\0';

    long long btime = -1;
    const char *p = statbuf;
    while (p && *p) {
        if (strncmp(p, "btime ", 6) == 0) {
            btime = strtoll(p + 6, NULL, 10);
            break;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }

    char uptime_buf[128] = {0};
    size_t ulen = 0;
    double uptime = -1.0;
    if (rasp_read_file_raw("/proc/uptime", uptime_buf, sizeof(uptime_buf) - 1, &ulen) == 0) {
        uptime_buf[ulen] = '\0';
        uptime = strtod(uptime_buf, NULL);
    }

    struct rasp_timespec boot;
    memset(&boot, 0, sizeof(boot));
    int boot_ok = rasp_raw_clock_gettime(RASP_CLOCK_BOOTTIME, &boot) == 0;

    long long now_s = rasp_now_ms() / 1000;
    long long est_btime = (boot_ok ? now_s - (long long)boot.tv_sec : -1);
    long long btime_diff = (btime > 0 && est_btime > 0)
                               ? (btime > est_btime ? btime - est_btime : est_btime - btime)
                               : -1;
    long long uptime_diff =
        (uptime > 0 && boot_ok)
            ? llabs((long long)uptime - (long long)boot.tv_sec)
            : -1;

    /* 真实内核里 btime ≈ now - BOOTTIME，且 /proc/uptime ≈ CLOCK_BOOTTIME */
    int time_hit = (btime_diff > 8) || (uptime_diff > 5);
    double conf = 0.0;
    if (btime_diff > 8) conf += 0.45;
    if (uptime_diff > 5) conf += 0.45;
    if (conf > 0.9) conf = 0.9;
    if (!time_hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "btime", btime);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "boottime_seconds", boot_ok ? (long long)boot.tv_sec : -1);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "uptime_seconds", uptime > 0 ? (long long)uptime : -1);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "btime_delta", btime_diff);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "uptime_delta", uptime_diff);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-006", "内核时序自洽性（btime / uptime / BOOTTIME）", "kernel", GRADE_INDIRECT,
              conf, time_hit, btime > 0 || uptime > 0, raw,
              (btime > 0 || uptime > 0) ? NULL : "time sources unavailable");
}

/* ------------------------------------------------------------------ KRN-007 */

static void check_errno_semantics(rasp_ctx_t *c)
{
    typedef struct {
        const char *path;
        int expect_success;
        int expect_errno;
        int allow_denied; /* 允许 EACCES/EPERM（SELinux 可能拒绝，不代表异常） */
        const char *label;
    } probe_t;

    static const probe_t probes[] = {
        {"/proc/self/__aegis_probe_noent__", 0, ENOENT, 0, "procfs-noent"},
        {"/dev/__aegis_probe_noent__", 0, ENOENT, 0, "dev-noent"},
        {"/system/bin/sh", 1, 0, 1, "system-sh"},
        {"/proc/version", 1, 0, 0, "proc-version"},
        {"", 0, ENOENT, 0, "empty-path"},
    };

    int checked = 0, anomalies = 0;
    char detail[384] = {0};

    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        int fd = rasp_raw_open(probes[i].path, RASP_O_RDONLY | RASP_O_CLOEXEC, 0);
        int err = errno;
        checked++;

        if (probes[i].expect_success) {
            if (fd < 0) {
                /* SELinux 策略可能拒绝读 /system/bin/sh，这属于环境限制而非异常 */
                if (probes[i].allow_denied && (err == EACCES || err == EPERM)) {
                    continue;
                }
                anomalies++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "%s(expected ok, got %d);",
                         probes[i].label, err);
            } else {
                rasp_raw_close(fd);
            }
        } else {
            if (fd >= 0) {
                rasp_raw_close(fd);
                anomalies++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "%s(expected %d, got success);",
                         probes[i].label, probes[i].expect_errno);
            } else if (err != probes[i].expect_errno) {
                /* 例如把 ENOENT 改写成 EACCES/EPERM：典型的"假装不存在"式过滤 */
                anomalies++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "%s(expected %d, got %d);",
                         probes[i].label, probes[i].expect_errno, err);
            }
        }
    }

    int hit = anomalies > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "probes", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anomalies", anomalies);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "KRN-007", "syscall 返回码语义异常探针", "kernel", GRADE_INDIRECT,
              hit ? 0.55 : 0.0, hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ INJ-005 */

static int code_path_allowed(const char *path)
{
    if (path == NULL || path[0] == '\0') return 1; /* 匿名段由 INJ-001 负责 */
    static const char *const prefixes[] = {
        "/system/", "/apex/", "/vendor/", "/product/", "/system_ext/", "/odm/",
        "/data/app/", "/data/dalvik-cache/", "/data/user/", "/data/data/", "/dev/",
        "/data/misc/", "/mnt/expand/",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (strncmp(path, prefixes[i], strlen(prefixes[i])) == 0) return 1;
    }
    if (strstr(path, "memfd:jit") != NULL) return 1;
    return 0;
}

static void check_code_mapping_origin(rasp_ctx_t *c)
{
    /* 模拟器的代码映射来源与真机差异极大，直接标记不可用，避免已知误报 */
    if (running_on_emulator()) {
        rasp_emit(c, "INJ-005", "非系统代码映射来源检测", "inject", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "emulator environment: code mapping origin is not comparable");
        return;
    }

    static rasp_map_t maps[1024];
    int n = rasp_maps_load(maps, 1024);
    if (n <= 0) {
        rasp_emit(c, "INJ-005", "非系统代码映射来源检测", "inject", GRADE_INDIRECT, 0.0, 0, 0, NULL,
                  "cannot read /proc/self/maps");
        return;
    }

    int exec_total = 0, offlist = 0;
    char examples[256] = {0};
    for (int i = 0; i < n; i++) {
        if (maps[i].perms[2] != 'x') continue;
        exec_total++;
        if (code_path_allowed(maps[i].path)) continue;
        offlist++;
        if (examples[0] == '\0') {
            snprintf(examples, sizeof(examples), "%s (0x%llx-0x%llx)", maps[i].path,
                     (unsigned long long)maps[i].start, (unsigned long long)maps[i].end);
        }
    }

    int hit = offlist > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "exec_mappings", exec_total);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "offlist_mappings", offlist);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "example", examples);
    rb_puts(&b, "}");
    rasp_emit(c, "INJ-005", "非系统代码映射来源检测", "inject", GRADE_INDIRECT,
              hit ? 0.7 : 0.0, hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ AHK-005 */

static int addr_executable(uint64_t addr, char *perm_out, size_t cap)
{
    static rasp_map_t maps[512];
    int n = rasp_maps_load(maps, 512);
    if (n <= 0) return -1;
    for (int i = 0; i < n; i++) {
        if (addr >= maps[i].start && addr < maps[i].end) {
            if (perm_out && cap > 0) snprintf(perm_out, cap, "%s", maps[i].perms);
            return maps[i].perms[2] == 'x';
        }
    }
    return 0;
}

static void check_function_segment(rasp_ctx_t *c)
{
    struct {
        const char *name;
        void *addr;
    } probes[3];
    int np = 0;
    probes[np].name = "rasp_emit(self)";
    probes[np++].addr = (void *)(uintptr_t)&rasp_emit;
    probes[np].name = "dlsym(libc)";
    probes[np++].addr = (void *)dlsym(RTLD_DEFAULT, "dlsym");
    probes[np].name = "open(libc)";
    probes[np++].addr = (void *)dlsym(RTLD_DEFAULT, "open");

    int checked = 0, bad = 0;
    char detail[384] = {0};

    for (int i = 0; i < np; i++) {
        if (probes[i].addr == NULL) continue;
        checked++;
        Dl_info info;
        memset(&info, 0, sizeof(info));
        int dl_ok = dladdr(probes[i].addr, &info) != 0 && info.dli_fbase != NULL;
        char perms[8] = {0};
        int exec = addr_executable((uint64_t)(uintptr_t)probes[i].addr, perms, sizeof(perms));

        /* 函数指针必须：① 能反向解析到某个模块；② 落在可执行段内 */
        if (!dl_ok || exec != 1) {
            bad++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(%s,%s);", probes[i].name,
                     dl_ok ? (info.dli_fname ? info.dli_fname : "?") : "no-dladdr",
                     exec == 1 ? "x" : (perms[0] ? perms : "unmapped"));
        }
    }

    int hit = bad > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "inconsistent", bad);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-005", "函数地址与可执行段一致性", "antihook", GRADE_STRONG,
              hit ? 0.9 : 0.0, hit, checked > 0, raw,
              checked > 0 ? NULL : "no probeable function");
    if (hit) c->anti_hook_hit = 1;
}

/* ------------------------------------------------------------------ AHK-006 */

static int read_mountinfo_via(int via_openat2, char *buf, size_t cap, size_t *out_len)
{
    int fd;
    if (via_openat2) {
        struct rasp_open_how how;
        memset(&how, 0, sizeof(how));
        how.flags = RASP_O_RDONLY | RASP_O_CLOEXEC;
        how.resolve = 0;
        fd = rasp_raw_openat2(RASP_AT_FDCWD, "/proc/self/mountinfo", &how, sizeof(how));
    } else {
        fd = rasp_raw_open("/proc/self/mountinfo", RASP_O_RDONLY | RASP_O_CLOEXEC, 0);
    }
    if (fd < 0) return -1;
    int rc = rasp_read_all_fd(fd, buf, cap - 1, out_len);
    rasp_raw_close(fd);
    return rc;
}

static void check_openat2(rasp_ctx_t *c)
{
    static char buf_open[64 * 1024];
    static char buf_open2[64 * 1024];

    /* openat2 由兼容性探测决定是否可用：不可用时明确标记，不做盲试 */
    if (!rasp_openat2_enabled()) {
        rasp_emit(c, "AHK-006", "openat2 与 openat 双路径一致性", "antihook", GRADE_STRONG, 0.0,
                  0, 0, NULL,
                  "openat2 disabled by compat probe (seccomp/unsupported kernel)");
        return;
    }

    int reads = 0, divergences = 0, openat2_unavailable = 0;
    size_t last_len1 = 0, last_len2 = 0;

    /* mountinfo 会在挂载变化时抖动，因此"不一致"必须复测一次才能成立 */
    for (int attempt = 0; attempt < 2; attempt++) {
        size_t len1 = 0, len2 = 0;
        if (read_mountinfo_via(0, buf_open, sizeof(buf_open), &len1) != 0) break;
        if (read_mountinfo_via(1, buf_open2, sizeof(buf_open2), &len2) != 0) {
            openat2_unavailable = 1;
            break;
        }
        reads++;
        last_len1 = len1;
        last_len2 = len2;
        if (len1 == len2 && memcmp(buf_open, buf_open2, len1) == 0) {
            divergences = 0;
            break;
        }
        divergences++;
    }

    if (reads == 0) {
        char raw[160];
        snprintf(raw, sizeof(raw), "{\"openat2_unavailable\":%s}",
                 openat2_unavailable ? "true" : "false");
        rasp_emit(c, "AHK-006", "openat2 与 openat 双路径一致性", "antihook", GRADE_STRONG, 0.0,
                  0, 0, raw,
                  openat2_unavailable ? "openat2 unavailable on this kernel" : "read failed");
        return;
    }

    int diverge = divergences >= 2;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "openat_len", (long long)last_len1);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "openat2_len", (long long)last_len2);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "attempts", reads);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "divergence", diverge);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-006", "openat2 与 openat 双路径一致性", "antihook", GRADE_STRONG,
              diverge ? 0.92 : 0.0, diverge, 1, raw, NULL);
    if (diverge) c->anti_hook_hit = 1;
}

/* ------------------------------------------------------------------ FOPS-001 */

static void check_dir_filter(rasp_ctx_t *c)
{
    int dir = rasp_raw_open("/proc/self/fd", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC, 0);
    if (dir < 0) {
        rasp_emit(c, "FOPS-001", "目录枚举与直接访问不一致（procfs 目录过滤）", "fops",
                  GRADE_STRONG, 0.0, 0, 0, NULL, "cannot open /proc/self/fd");
        return;
    }

    enum { MAXFD = 512 };
    static unsigned char listed[MAXFD];
    memset(listed, 0, sizeof(listed));

    char dbuf[8192];
    int listed_count = 0;
    for (;;) {
        long got = rasp_raw_getdents64(dir, dbuf, sizeof(dbuf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(dbuf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            int idx = atoi(d->d_name);
            if (idx >= 0 && idx < MAXFD) listed[idx] = 1;
            listed_count++;
        }
    }

    /* 目录项被过滤时，getdents 看不到，但按名字直接访问仍然成功 */
    int hidden = 0;
    char detail[256] = {0};
    for (int n = 0; n < MAXFD; n++) {
        if (listed[n]) continue;
        char name[16];
        snprintf(name, sizeof(name), "%d", n);
        char target[192];
        long r = rasp_raw_readlinkat(dir, name, target, sizeof(target) - 1);
        if (r > 0) {
            hidden++;
            if (detail[0] == '\0') {
                target[r] = '\0';
                snprintf(detail, sizeof(detail), "fd %d hidden from readdir -> %s", n, target);
            }
        }
    }
    rasp_raw_close(dir);

    int hit = hidden > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "listed_entries", listed_count);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "hidden_entries", hidden);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "FOPS-001", "目录枚举与直接访问不一致（procfs 目录过滤）", "fops", GRADE_STRONG,
              hit ? 0.85 : 0.0, hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ ZYS-007 */

static int thread_name_suspicious(const char *comm)
{
    /* 只保留与隐藏套件强相关的名字，避免 "hook"/"inline" 这类通用词误报 */
    static const char *const keys[] = {"zygisk", "lspd", "lsposed", "riru",
                                       "magisk", "ksud", "injected", "payload_"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (rasp_contains_ci(comm, keys[i])) return 1;
    }
    return 0;
}

static void check_thread_names(rasp_ctx_t *c)
{
    int dir = rasp_raw_open("/proc/self/task", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC,
                            0);
    if (dir < 0) {
        rasp_emit(c, "ZYS-007", "异常线程名与线程注入痕迹", "zygisk", GRADE_WEAK, 0.0, 0, 0, NULL,
                  "cannot open /proc/self/task");
        return;
    }

    char dbuf[8192];
    int threads = 0, suspicious = 0;
    char detail[256] = {0};

    for (;;) {
        long got = rasp_raw_getdents64(dir, dbuf, sizeof(dbuf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(dbuf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            threads++;
            char comm[64] = {0};
            size_t clen = 0;
            int err = 0, via = 0;
            if (rasp_read_proc((pid_t)atoi(d->d_name), "comm", comm, sizeof(comm) - 1, &clen, &err,
                               &via) != 0) {
                continue;
            }
            comm[clen] = '\0';
            while (clen > 0 && (comm[clen - 1] == '\n' || comm[clen - 1] == '\r')) {
                comm[--clen] = '\0';
            }
            if (thread_name_suspicious(comm)) {
                suspicious++;
                if (detail[0] == '\0') {
                    snprintf(detail, sizeof(detail), "tid=%s comm=%s", d->d_name, comm);
                }
            }
        }
    }
    rasp_raw_close(dir);

    int hit = suspicious > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "threads", threads);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "suspicious", suspicious);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "ZYS-007", "异常线程名与线程注入痕迹", "zygisk", GRADE_WEAK,
              hit ? 0.4 : 0.0, hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ 模块入口 */

void rasp_check_extra(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2500);
    check_statfs_flags(c);
    if (!rasp_deadline_hit(c)) check_mount_dev(c);
    if (!rasp_deadline_hit(c)) check_time_sanity(c);
    if (!rasp_deadline_hit(c)) check_errno_semantics(c);
    if (!rasp_deadline_hit(c)) check_code_mapping_origin(c);
    if (!rasp_deadline_hit(c)) check_function_segment(c);
    if (!rasp_deadline_hit(c)) check_openat2(c);
    if (!rasp_deadline_hit(c)) check_dir_filter(c);
    if (!rasp_deadline_hit(c)) check_thread_names(c);
}
