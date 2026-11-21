/*
 * rasp_checks_antihook.c —— 第 8 类：反 Hook 自校验
 *
 * 检测项：
 *   AHK-001 libc 关键函数入口完整性校验【强】
 *   AHK-002 直调 syscall 与 libc 调用结果一致性校验【强】
 *   AHK-003 检测代码段内存完整性校验【强】
 *   AHK-004 JNI 函数表完整性校验【强】
 *
 * 任一命中都会把 anti_hook_hit 置位，最终判定直接进入高风险（见打分模型）。
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ 代码快照 */

#define SNAP_MAX 4

typedef struct {
    const char *name;
    const unsigned char *addr;
    size_t len;
    uint64_t hash;
    int valid;
} code_snap_t;

static code_snap_t g_snaps[SNAP_MAX];
static int g_snap_count = 0;

/* 该函数在 JNI_OnLoad 中调用，记录自身热代码的初始指纹 */
void rasp_ahk_snapshot(void)
{
    static const size_t lens[SNAP_MAX] = {64, 64, 64, 64};
    g_snap_count = 0;
    if (g_snap_count < SNAP_MAX) {
        g_snaps[g_snap_count].name = "rasp_emit";
        g_snaps[g_snap_count].addr = (const unsigned char *)(uintptr_t)&rasp_emit;
        g_snaps[g_snap_count].len = lens[g_snap_count];
        g_snaps[g_snap_count].hash =
            rasp_hash64(g_snaps[g_snap_count].addr, g_snaps[g_snap_count].len);
        g_snaps[g_snap_count].valid = 1;
        g_snap_count++;
    }
    if (g_snap_count < SNAP_MAX) {
        g_snaps[g_snap_count].name = "rasp_check_antihook";
        g_snaps[g_snap_count].addr = (const unsigned char *)(uintptr_t)&rasp_check_antihook;
        g_snaps[g_snap_count].len = lens[g_snap_count];
        g_snaps[g_snap_count].hash =
            rasp_hash64(g_snaps[g_snap_count].addr, g_snaps[g_snap_count].len);
        g_snaps[g_snap_count].valid = 1;
        g_snap_count++;
    }
}

/* ------------------------------------------------------------------ AHK-001 */

typedef struct {
    const char *name;
    void *addr;
} lc_probe_t;

static void check_libc_entries(rasp_ctx_t *c)
{
    void *h = dlopen("libc.so", RTLD_NOW);
    void *hh = h ? h : RTLD_DEFAULT;
    lc_probe_t probes[6] = {
        {"open", (void *)dlsym(hh, "open")},
        {"openat", (void *)dlsym(hh, "openat")},
        {"read", (void *)dlsym(hh, "read")},
        {"close", (void *)dlsym(hh, "close")},
        {"mmap", (void *)dlsym(hh, "mmap")},
        {"__system_property_get", (void *)dlsym(hh, "__system_property_get")},
    };

    int checked = 0, suspicious = 0;
    char detail[640] = {0};
    for (int i = 0; i < 6; i++) {
        if (probes[i].addr == NULL) continue;
        char d[192] = {0};
        int rc = rasp_check_function_entry(probes[i].addr, "libc.so", d, sizeof(d));
        if (rc < 0) continue;
        checked++;
        if (rc > 0) {
            suspicious++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s:%s;", probes[i].name, d);
        }
    }
    if (h) dlclose(h);

    if (suspicious > 0) c->anti_hook_hit = 1;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "suspicious", suspicious);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-001", "libc 关键函数入口完整性校验", "antihook", GRADE_STRONG,
              suspicious > 0 ? 0.95 : 0.0, suspicious > 0, checked > 0, raw,
              checked > 0 ? NULL : "cannot resolve libc symbols");
}

/* ------------------------------------------------------------------ AHK-002 */

static void check_raw_vs_libc(rasp_ctx_t *c)
{
    static char via_raw[64 * 1024];
    static char via_libc[64 * 1024];
    size_t l1 = 0, l2 = 0;

    int ok1 = rasp_read_file_raw("/proc/self/status", via_raw, sizeof(via_raw) - 1, &l1) == 0;
    int ok2 = rasp_read_file_libc("/proc/self/status", via_libc, sizeof(via_libc) - 1, &l2) == 0;

    int diff = 0;
    char detail[256] = {0};
    if (ok1 && ok2) {
        if (l1 != l2 || memcmp(via_raw, via_libc, l1 < l2 ? l1 : l2) != 0) {
            diff = 1;
            snprintf(detail, sizeof(detail), "status read differs: raw=%zu libc=%zu", l1, l2);
        }
    }

    /* statx（直调）与 libc stat 的元信息比对 */
    struct rasp_statx stx;
    struct stat st;
    memset(&stx, 0, sizeof(stx));
    memset(&st, 0, sizeof(st));
    int ok3 = rasp_raw_statx(RASP_AT_FDCWD, "/system/build.prop", 0, RASP_STATX_BASIC_STATS,
                             &stx) == 0;
    int ok4 = stat("/system/build.prop", &st) == 0;
    int stat_checked = 0;
    if (ok3 && ok4) {
        stat_checked = 1;
        if (stx.stx_ino != (uint64_t)st.st_ino || stx.stx_size != (uint64_t)st.st_size) {
            diff = 1;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l,
                     "stat differs: ino %llu/%llu size %llu/%llu", (unsigned long long)stx.stx_ino,
                     (unsigned long long)st.st_ino, (unsigned long long)stx.stx_size,
                     (unsigned long long)st.st_size);
        }
    }

    /* getpid 直调与 libc 一致性 */
    pid_t raw_pid = rasp_raw_getpid();
    pid_t libc_pid = getpid();
    if (raw_pid != libc_pid) {
        diff = 1;
        size_t l = strlen(detail);
        snprintf(detail + l, sizeof(detail) - l, "getpid %d/%d", (int)raw_pid, (int)libc_pid);
    }

    if (diff > 0) c->anti_hook_hit = 1;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_bool(&b, "status_verified", ok1 && ok2);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "stat_verified", stat_checked);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "divergence", diff);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-002", "直调 syscall 与 libc 调用结果一致性校验", "antihook", GRADE_STRONG,
              diff ? 0.95 : 0.0, diff, ok1 || ok4, raw,
              (ok1 || ok4) ? NULL : "no readable comparison target");
}

/* ------------------------------------------------------------------ AHK-003 */

static void check_code_integrity(rasp_ctx_t *c)
{
    int tampered = 0;
    char detail[512] = {0};
    for (int i = 0; i < g_snap_count; i++) {
        if (!g_snaps[i].valid) continue;
        uint64_t now = rasp_hash64(g_snaps[i].addr, g_snaps[i].len);
        if (now != g_snaps[i].hash) {
            tampered++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(hash %llx->%llx);", g_snaps[i].name,
                     (unsigned long long)g_snaps[i].hash, (unsigned long long)now);
        }
    }

#if defined(__aarch64__)
    /* 代码段是否被写入 BRK（0xD4200000）——典型断点式 Hook */
    for (int i = 0; i < g_snap_count; i++) {
        const unsigned char *p = g_snaps[i].addr;
        for (size_t off = 0; off + 4 <= g_snaps[i].len; off += 4) {
            uint32_t insn = 0;
            memcpy(&insn, p + off, sizeof(insn));
            if ((insn & 0xFFE0001Fu) == 0xD4200000u) {
                tampered++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "%s:BRK@%zu;", g_snaps[i].name, off);
                break;
            }
        }
    }
#endif

    if (tampered > 0) c->anti_hook_hit = 1;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "snapshots", g_snap_count);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "tampered", tampered);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-003", "检测代码段内存完整性校验", "antihook", GRADE_STRONG,
              tampered > 0 ? 0.95 : 0.0, tampered > 0, g_snap_count > 0, raw,
              g_snap_count > 0 ? NULL : "no snapshot taken");
}

/* ------------------------------------------------------------------ AHK-004 */

static void check_jni_table(rasp_ctx_t *c)
{
    char detail[512] = {0};
    int tampered = rasp_jni_table_verify(detail, sizeof(detail));
    if (tampered > 0) c->anti_hook_hit = 1;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "tampered", tampered);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "AHK-004", "JNI 函数表完整性校验", "antihook", GRADE_STRONG,
              tampered > 0 ? 0.95 : 0.0, tampered > 0, 1, raw, NULL);
}

void rasp_check_antihook(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 1500);
    check_libc_entries(c);
    if (!rasp_deadline_hit(c)) check_raw_vs_libc(c);
    check_code_integrity(c);
    check_jni_table(c);
}
