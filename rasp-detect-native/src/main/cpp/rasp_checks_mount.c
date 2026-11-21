/*
 * rasp_checks_mount.c —— 第 1 类：Mount Namespace & 文件视图隔离
 *
 * 检测项：
 *   MNT-001 挂载视图自洽性（mountinfo 挂载 ID vs statx stx_mnt_id）【强】
 *   MNT-002 跨进程 mountinfo 结构比对（pidfd 打开 init/system_server）【强】
 *   MNT-003 同路径文件 stat 元信息跨视图比对【强】
 *   MNT-004 匿名 overlay / tmpfs 覆盖系统分区痕迹【强】
 *   MNT-005 挂载传播属性（propagation）异常【间接】
 *   MNT-006 多路径读取结果一致性校验（mountinfo / mounts / proc-root）【间接】
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MI_MAX_IDS 768
#define MI_MAX_LINES 1024

typedef struct {
    int count;
    int id_count;
    uint64_t ids[MI_MAX_IDS];
    int overlay_on_system;
    int tmpfs_on_system;
    int rw_system;
    int data_adb_mount;
    int shared_prop;
    int suspicious_source;
    char example[192];
} mountinfo_t;

static int id_present(const mountinfo_t *mi, uint64_t id)
{
    for (int i = 0; i < mi->id_count; i++) {
        if (mi->ids[i] == id) return 1;
    }
    return 0;
}

static int is_system_path(const char *p)
{
    if (p == NULL) return 0;
    return strncmp(p, "/system", 7) == 0 || strncmp(p, "/vendor", 7) == 0 ||
           strncmp(p, "/product", 8) == 0 || strncmp(p, "/system_ext", 11) == 0 ||
           strncmp(p, "/odm", 4) == 0;
}

static int parse_mountinfo(const char *buf, mountinfo_t *mi)
{
    memset(mi, 0, sizeof(*mi));
    if (buf == NULL) return -1;

    char *copy = strdup(buf);
    if (copy == NULL) return -1;

    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line != NULL;
         line = strtok_r(NULL, "\n", &save)) {
        if (++mi->count > MI_MAX_LINES) break;

        char *tok[64];
        int nt = 0;
        char *p = line;
        while (*p && nt < 64) {
            while (*p == ' ') p++;
            if (*p == '\0') break;
            tok[nt++] = p;
            while (*p && *p != ' ') p++;
            if (*p) *p++ = '\0';
        }
        if (nt < 6) continue;

        if (mi->id_count < MI_MAX_IDS) {
            mi->ids[mi->id_count++] = strtoull(tok[0], NULL, 10);
        }
        const char *mnt_point = tok[4];
        const char *mnt_opts = tok[5];

        const char *fstype = NULL;
        const char *source = NULL;
        for (int i = 6; i < nt; i++) {
            if (strcmp(tok[i], "-") == 0 && i + 2 < nt) {
                fstype = tok[i + 1];
                source = tok[i + 2];
                break;
            }
        }

        if (fstype && strcmp(fstype, "overlay") == 0 && is_system_path(mnt_point)) {
            mi->overlay_on_system = 1;
            if (mi->example[0] == '\0') {
                snprintf(mi->example, sizeof(mi->example), "overlay on %s (src=%s)", mnt_point,
                         source ? source : "?");
            }
        }
        if (fstype && strcmp(fstype, "tmpfs") == 0 && is_system_path(mnt_point)) {
            mi->tmpfs_on_system = 1;
            if (mi->example[0] == '\0') {
                snprintf(mi->example, sizeof(mi->example), "tmpfs on %s", mnt_point);
            }
        }
        if (is_system_path(mnt_point) && strstr(mnt_opts, "rw") != NULL) {
            mi->rw_system = 1;
        }
        if (strstr(mnt_point, "/data/adb") != NULL ||
            (source && strstr(source, "/data/adb") != NULL)) {
            mi->data_adb_mount = 1;
        }
        if (strstr(mnt_opts, "shared:") != NULL) {
            mi->shared_prop++;
            if ((is_system_path(mnt_point) || strncmp(mnt_point, "/data", 5) == 0) &&
                mi->example[0] == '\0') {
                snprintf(mi->example, sizeof(mi->example), "propagation %s on %s", mnt_opts,
                         mnt_point);
            }
        }
        if (source && (strstr(source, "KSU") != NULL || strstr(source, "ksu") != NULL ||
                       strstr(source, "magisk") != NULL || strstr(source, "worker") != NULL)) {
            mi->suspicious_source = 1;
            if (mi->example[0] == '\0') {
                snprintf(mi->example, sizeof(mi->example), "source=%s on %s", source, mnt_point);
            }
        }
    }
    free(copy);
    return 0;
}

/* 同一路径在 mountinfo 中出现多次（stacked mount）——隐藏套件的典型手法 */
static int count_duplicate_mountpoints(const char *buf, char *example, size_t cap)
{
    if (buf == NULL) return 0;
    char *copy = strdup(buf);
    if (copy == NULL) return 0;
    char *save = NULL;
    static char paths[192][128];
    int np = 0, dup = 0;
    for (char *line = strtok_r(copy, "\n", &save); line != NULL && np < 192;
         line = strtok_r(NULL, "\n", &save)) {
        char f[128];
        if (rasp_field(line, 4, f, sizeof(f)) != 0) continue;
        int seen = 0;
        for (int i = 0; i < np; i++) {
            if (strcmp(paths[i], f) == 0) {
                seen = 1;
                break;
            }
        }
        if (seen) {
            dup++;
            if (example && cap > 0 && example[0] == '\0') {
                snprintf(example, cap, "duplicate mountpoint %s", f);
            }
        } else {
            snprintf(paths[np++], sizeof(paths[0]), "%s", f);
        }
    }
    free(copy);
    return dup;
}

static void check_self_consistency(rasp_ctx_t *c, const mountinfo_t *mi)
{
    static const char *paths[] = {"/system", "/system/bin", "/system/etc", "/vendor",
                                  "/product", "/data", "/data/app", "/proc", "/dev"};
    int checked = 0, missing = 0;
    char missing_paths[256] = {0};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        struct rasp_statx stx;
        memset(&stx, 0, sizeof(stx));
        if (rasp_raw_statx(RASP_AT_FDCWD, paths[i], 0,
                           RASP_STATX_BASIC_STATS | 0x1000u /* STATX_MNT_ID */, &stx) != 0) {
            continue;
        }
        if (stx.stx_mnt_id == 0) continue; /* 内核 < 5.8 不返回 mnt_id */
        checked++;
        if (!id_present(mi, stx.stx_mnt_id)) {
            missing++;
            size_t l = strlen(missing_paths);
            if (l + strlen(paths[i]) + 2 < sizeof(missing_paths)) {
                if (l) strcat(missing_paths, ",");
                strcat(missing_paths, paths[i]);
            }
        }
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "paths_checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mnt_ids_missing", missing);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "missing_paths", missing_paths);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mountinfo_entries", mi->count);
    rb_puts(&b, "}");

    rasp_emit(c, "MNT-001", "挂载视图自洽性校验（statx mnt_id vs mountinfo）", "mount",
              GRADE_STRONG, missing > 0 ? 0.9 : 0.0, missing > 0, checked > 0, raw, NULL);
}

static void check_cross_process_mount(rasp_ctx_t *c, const mountinfo_t *self_mi)
{
    static const char *targets[] = {"init", "system_server"};
    static const pid_t fixed_pids[] = {1, 1000};
    static mountinfo_t other;
    int compared = 0, diff = 0;
    char detail[512] = {0};
    char errors[256] = {0};

    for (int i = 0; i < 2; i++) {
        pid_t pid = fixed_pids[i];
        if (i == 1) {
            pid_t found = rasp_find_proc_pid("system_server", 512);
            if (found > 0) pid = found;
        }
        static char buf[96 * 1024];
        size_t len = 0;
        int err = 0, via = 0;
        if (rasp_read_proc(pid, "mountinfo", buf, sizeof(buf), &len, &err, &via) != 0) {
            size_t l = strlen(errors);
            snprintf(errors + l, sizeof(errors) - l, "%s=%d(%s);", targets[i], err,
                     strerror(err));
            continue;
        }
        if (parse_mountinfo(buf, &other) != 0) continue;
        compared++;

        int overlay_diff = (other.overlay_on_system != self_mi->overlay_on_system);
        int tmpfs_diff = (other.tmpfs_on_system != self_mi->tmpfs_on_system);
        int count_ratio = (self_mi->count > 0 && other.count > 0)
                              ? (self_mi->count * 100 / other.count)
                              : 100;
        if (overlay_diff || tmpfs_diff || count_ratio < 90 || count_ratio > 115) {
            diff++;
        }
        size_t l = strlen(detail);
        snprintf(detail + l, sizeof(detail) - l,
                 "%s{pid=%d,entries=%d,self=%d,overlay=%d/%d,tmpfs=%d/%d,via_pidfd=%d};",
                 targets[i], (int)pid, other.count, self_mi->count, other.overlay_on_system,
                 self_mi->overlay_on_system, other.tmpfs_on_system, self_mi->tmpfs_on_system,
                 via);
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "compared", compared);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "inconsistent", diff);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "unavailable", errors);
    rb_puts(&b, "}");

    rasp_emit(c, "MNT-002", "跨进程 mountinfo 结构比对（pidfd → init/system_server）", "mount",
              GRADE_STRONG, diff > 0 ? 0.85 : 0.0, diff > 0, compared > 0, raw,
              compared > 0 ? NULL
                           : "cross-process mountinfo unreadable (SELinux/ptrace scope)");
}

static void check_cross_process_stat(rasp_ctx_t *c)
{
    static const char *probe = "/system/bin/app_process64";
    static const char *probe_alt = "/proc/self/root/system/bin/app_process64";

    struct rasp_statx a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    int ok_a = rasp_raw_statx(RASP_AT_FDCWD, probe, 0, RASP_STATX_BASIC_STATS, &a) == 0;
    int ok_b = rasp_raw_statx(RASP_AT_FDCWD, probe_alt, 0, RASP_STATX_BASIC_STATS, &b) == 0;

    int compared = 0, inconsistent = 0;
    char detail[384] = {0};

    if (ok_a && ok_b) {
        compared++;
        if (a.stx_ino != b.stx_ino || a.stx_dev_major != b.stx_dev_major ||
            a.stx_dev_minor != b.stx_dev_minor || a.stx_size != b.stx_size) {
            inconsistent++;
            snprintf(detail, sizeof(detail),
                     "self/root 视图不一致: ino %llu/%llu size %llu/%llu dev %u:%u/%u:%u",
                     (unsigned long long)a.stx_ino, (unsigned long long)b.stx_ino,
                     (unsigned long long)a.stx_size, (unsigned long long)b.stx_size,
                     a.stx_dev_major, a.stx_dev_minor, b.stx_dev_major, b.stx_dev_minor);
        } else {
            snprintf(detail, sizeof(detail), "self/root 一致: ino=%llu size=%llu",
                     (unsigned long long)a.stx_ino, (unsigned long long)a.stx_size);
        }
    }

    /* 与 system_server 的 root 视图比对（多数 Android 15 环境 EACCES，记录为不可用） */
    pid_t sp = rasp_find_proc_pid("system_server", 512);
    int xproc_checked = 0, xproc_diff = 0;
    if (sp > 0) {
        int pfd = rasp_pidfd_open_compat(sp);
        if (pfd >= 0) {
            struct rasp_statx c_stx;
            memset(&c_stx, 0, sizeof(c_stx));
            if (rasp_raw_statx(pfd, "root/system/bin/app_process64", 0, RASP_STATX_BASIC_STATS,
                               &c_stx) == 0) {
                xproc_checked = 1;
                if (ok_a && (c_stx.stx_ino != a.stx_ino || c_stx.stx_size != a.stx_size ||
                             c_stx.stx_dev_major != a.stx_dev_major ||
                             c_stx.stx_dev_minor != a.stx_dev_minor)) {
                    xproc_diff = 1;
                }
            }
            rasp_raw_close(pfd);
        }
    }

    int hit = inconsistent > 0 || xproc_diff > 0;
    char raw[RASP_RAW_MAX];
    rasp_buf_t bf;
    rb_init(&bf, raw, sizeof(raw));
    rb_puts(&bf, "{");
    rb_json_kv_int(&bf, "self_checked", compared);
    rb_puts(&bf, ",");
    rb_json_kv_int(&bf, "self_inconsistent", inconsistent);
    rb_puts(&bf, ",");
    rb_json_kv_int(&bf, "xproc_checked", xproc_checked);
    rb_puts(&bf, ",");
    rb_json_kv_int(&bf, "xproc_inconsistent", xproc_diff);
    rb_puts(&bf, ",");
    rb_json_kv_str(&bf, "detail", detail);
    rb_puts(&bf, ",");
    rb_json_kv_int(&bf, "errno_self", ok_a ? 0 : errno);
    rb_puts(&bf, "}");
    rasp_emit(c, "MNT-003", "同路径文件 stat 元信息跨视图比对", "mount", GRADE_STRONG,
              hit ? 0.85 : 0.0, hit, (compared + xproc_checked) > 0, raw,
              (compared + xproc_checked) > 0 ? NULL : "no readable view for stat comparison");
}

static void check_overlay(rasp_ctx_t *c, const mountinfo_t *mi, int dup)
{
    int hit = mi->overlay_on_system || mi->tmpfs_on_system || mi->data_adb_mount ||
              mi->suspicious_source || dup > 0;
    double conf = 0.0;
    if (mi->overlay_on_system) conf += 0.5;
    if (mi->tmpfs_on_system) conf += 0.3;
    if (mi->data_adb_mount) conf += 0.4;
    if (mi->suspicious_source) conf += 0.5;
    if (dup > 0) conf += 0.3;
    if (conf > 0.95) conf = 0.95;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_bool(&b, "overlay_on_system", mi->overlay_on_system);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "tmpfs_on_system", mi->tmpfs_on_system);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "data_adb_mount", mi->data_adb_mount);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "ksu_or_magisk_source", mi->suspicious_source);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "duplicate_mountpoints", dup);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "example", mi->example);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mount_entries", mi->count);
    rb_puts(&b, "}");
    rasp_emit(c, "MNT-004", "匿名 overlay / tmpfs 覆盖系统分区痕迹", "mount", GRADE_STRONG, conf,
              hit, 1, raw, NULL);
}

static void check_propagation(rasp_ctx_t *c, const mountinfo_t *mi)
{
    int hit = mi->shared_prop > 0 &&
              (mi->rw_system || mi->tmpfs_on_system || mi->overlay_on_system);
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "shared_mounts", mi->shared_prop);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "system_rw", mi->rw_system);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "example", mi->example);
    rb_puts(&b, "}");
    rasp_emit(c, "MNT-005", "挂载点 propagation 属性异常", "mount", GRADE_INDIRECT,
              hit ? 0.5 : 0.0, hit, 1, raw, NULL);
}

static void check_multi_path(rasp_ctx_t *c, const char *mountinfo_buf)
{
    static char mounts_buf[48 * 1024];
    size_t len = 0;
    int rc_raw = rasp_read_file_raw("/proc/self/mounts", mounts_buf, sizeof(mounts_buf), &len);
    static char mounts_libc[48 * 1024];
    size_t len2 = 0;
    int rc_libc =
        rasp_read_file_libc("/proc/self/mounts", mounts_libc, sizeof(mounts_libc), &len2);

    int divergence = 0;
    char detail[256] = {0};
    if (rc_raw == 0 && rc_libc == 0) {
        if (len != len2 || memcmp(mounts_buf, mounts_libc, len < len2 ? len : len2) != 0) {
            divergence = 1;
            snprintf(detail, sizeof(detail), "raw/libc read of /proc/self/mounts differs");
        }
    }

    int mounts_lines = rc_raw == 0 ? rasp_count_lines(mounts_buf) : 0;
    int mi_lines = rasp_count_lines(mountinfo_buf);
    int count_gap = (mounts_lines > 0 && mi_lines > 0 &&
                     (mounts_lines * 100 / mi_lines < 80 || mounts_lines * 100 / mi_lines > 125))
                        ? 1
                        : 0;
    if (count_gap && detail[0] == '\0') {
        snprintf(detail, sizeof(detail), "mounts(%d) vs mountinfo(%d) line gap", mounts_lines,
                 mi_lines);
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "mounts_lines", mounts_lines);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mountinfo_lines", mi_lines);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "raw_libc_divergence", divergence);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "count_gap", count_gap);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "MNT-006", "多路径读取一致性（mountinfo/mounts/raw+libc）", "mount",
              GRADE_INDIRECT, (divergence || count_gap) ? 0.6 : 0.0, divergence || count_gap, 1,
              raw, NULL);
}

void rasp_check_mount(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2500);

    static char mi_buf[128 * 1024];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "mountinfo", mi_buf, sizeof(mi_buf), &len, &err, &via) != 0) {
        char raw[256];
        snprintf(raw, sizeof(raw), "{\"errno\":%d,\"msg\":\"%s\"}", err, strerror(err));
        rasp_emit(c, "MNT-001", "挂载视图自洽性校验（statx mnt_id vs mountinfo）", "mount",
                  GRADE_STRONG, 0.0, 0, 0, raw, "cannot read /proc/self/mountinfo");
        return;
    }

    mountinfo_t mi;
    parse_mountinfo(mi_buf, &mi);
    int dup = count_duplicate_mountpoints(mi_buf, NULL, 0);

    check_self_consistency(c, &mi);
    /* 分级调度：跨进程 /proc 读取属高开销项，快速模式跳过 */
    if (!c->fast_mode && !rasp_deadline_hit(c)) check_cross_process_mount(c, &mi);
    if (!c->fast_mode && !rasp_deadline_hit(c)) check_cross_process_stat(c);
    check_overlay(c, &mi, dup);
    check_propagation(c, &mi);
    if (!c->fast_mode && !rasp_deadline_hit(c)) check_multi_path(c, mi_buf);
}
