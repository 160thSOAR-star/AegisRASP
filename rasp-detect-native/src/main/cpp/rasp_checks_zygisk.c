/*
 * rasp_checks_zygisk.c —— 第 5 类：Zygisk / Shamiko / LSPosed / HMA Next 专项痕迹
 *
 * 检测项：
 *   ZYS-001 Zygote 注入间接痕迹【间接】
 *   ZYS-002 Zygisk native bridge 异常【间接】
 *   ZYS-003 Shamiko 挂载隔离特征【强】
 *   ZYS-004 LSPosed 方法 Hook 间接特征【强】
 *   多路径包列表查询（ZYS-005）与 Binder 一致性（ZYS-006）由 Java 层执行后回注本引擎，
 *   原因：这两项必须调用 PackageManager / binder，native 层无对应合法接口。
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>

static void prop_get(const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    __system_property_get(key, out);
    if (strlen(out) >= cap) out[cap - 1] = '\0';
}

/* ------------------------------------------------------------------ ZYS-001 */

static void check_zygote_injection(rasp_ctx_t *c)
{
    rasp_maps_stats_t st;
    if (rasp_maps_stats(&st) != 0) {
        rasp_emit(c, "ZYS-001", "Zygote 注入间接痕迹检测", "zygisk", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "cannot read /proc/self/maps");
        return;
    }

    /* 正常 App 不应存在 rwx 段，也不应有匿名可执行段或非 JIT 的 memfd 可执行段 */
    int hit = st.rwx > 1 || st.anon_exec > 3 || st.memfd_exec > 0 || st.deleted_exec > 0 ||
              st.suspicious_path > 0;
    double conf = 0.0;
    if (st.rwx > 1) conf += 0.55;
    if (st.anon_exec > 3) conf += 0.30;
    if (st.memfd_exec > 0) conf += 0.5;
    if (st.deleted_exec > 0) conf += 0.45;
    if (st.suspicious_path > 0) conf += 0.7;
    if (conf > 0.95) conf = 0.95;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "map_total", st.total);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "rwx_segments", st.rwx);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anon_exec", st.anon_exec);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "memfd_exec", st.memfd_exec);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "deleted_exec", st.deleted_exec);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "suspicious_modules", st.suspicious_path);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "example", st.suspicious_example);
    rb_puts(&b, "}");
    rasp_emit(c, "ZYS-001", "Zygote 注入间接痕迹检测", "zygisk", GRADE_INDIRECT, conf, hit, 1, raw,
              NULL);
}

/* ------------------------------------------------------------------ ZYS-002 */

static void check_native_bridge(rasp_ctx_t *c)
{
    char bridge[PROP_VALUE_MAX] = {0}, persist_bridge[PROP_VALUE_MAX] = {0};
    prop_get("ro.dalvik.vm.native.bridge", bridge, sizeof(bridge));
    prop_get("persist.sys.nativebridge", persist_bridge, sizeof(persist_bridge));

    int suspicious = 0;
    if (bridge[0] != '\0' && strcmp(bridge, "0") != 0) suspicious++;
    if (persist_bridge[0] != '\0' && strcmp(persist_bridge, "0") != 0) suspicious++;

    uint64_t s1 = 0, e1 = 0;
    int has_nativebridge = rasp_maps_find_module("libnativebridge.so", &s1, &e1) == 0;
    int has_houdini = rasp_maps_find_module("libhoudini.so", &s1, &e1) == 0;
    int has_ndk_trans = rasp_maps_find_module("libndk_translation.so", &s1, &e1) == 0;
    /* 被 Zygisk 替换的 native bridge 会以非系统路径出现 */
    int bridge_off_system = 0;
    static rasp_map_t maps[512];
    int n = rasp_maps_load(maps, 512);
    for (int i = 0; i < n; i++) {
        if (strstr(maps[i].path, "nativebridge") || strstr(maps[i].path, "houdini")) {
            if (strncmp(maps[i].path, "/system/", 8) != 0 &&
                strncmp(maps[i].path, "/apex/", 6) != 0) {
                bridge_off_system = 1;
            }
        }
    }

    rasp_maps_stats_t st;
    int art_ok = (rasp_maps_stats(&st) == 0);
    int art_code_writable = art_ok && st.art_writable > 0;

    int hit = suspicious > 0 || bridge_off_system || art_code_writable;
    double conf = 0.0;
    if (suspicious > 0) conf += 0.4;
    if (bridge_off_system) conf += 0.6;
    if (art_code_writable) conf += 0.55;
    if (conf > 0.9) conf = 0.9;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "ro.dalvik.vm.native.bridge", bridge);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "persist.sys.nativebridge", persist_bridge);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "libnativebridge_mapped", has_nativebridge);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "houdini_mapped", has_houdini || has_ndk_trans);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "bridge_off_system", bridge_off_system);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "libart_code_writable", art_code_writable);
    rb_puts(&b, "}");
    rasp_emit(c, "ZYS-002", "Zygisk native bridge 异常检测", "zygisk", GRADE_INDIRECT, conf, hit, 1,
              raw, NULL);
}

/* ------------------------------------------------------------------ ZYS-003 */

static void check_shamiko(rasp_ctx_t *c)
{
    static char mi[128 * 1024];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "mountinfo", mi, sizeof(mi) - 1, &len, &err, &via) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", err);
        rasp_emit(c, "ZYS-003", "Shamiko 挂载隔离特征", "zygisk", GRADE_STRONG, 0.0, 0, 0, raw,
                  "cannot read mountinfo");
        return;
    }
    mi[len] = '\0';

    int tmpfs_system = 0, worker_src = 0, ksu_src = 0, zero_size_system = 0, umount_marker = 0;
    int lines = 0;
    const char *p = mi;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        char line[1024];
        if (llen >= sizeof(line)) llen = sizeof(line) - 1;
        memcpy(line, p, llen);
        line[llen] = '\0';
        lines++;

        int is_tmpfs = strstr(line, " - tmpfs ") != NULL;
        int is_system = strstr(line, " /system") != NULL || strstr(line, " /vendor") != NULL ||
                        strstr(line, " /product") != NULL;
        if (is_tmpfs && is_system) tmpfs_system++;
        if (strstr(line, "worker") != NULL) worker_src++;
        if (strstr(line, "KSU") != NULL || strstr(line, "ksu") != NULL) ksu_src++;
        if (is_system && strstr(line, "size=0") != NULL) zero_size_system++;
        if (strstr(line, " /data/adb") != NULL) umount_marker++;

        if (eol == NULL) break;
        p = eol + 1;
    }

    int hit = tmpfs_system > 0 || worker_src > 0 || ksu_src > 0 || zero_size_system > 0 ||
              umount_marker > 0;
    double conf = 0.0;
    if (tmpfs_system > 0) conf += 0.55;
    if (worker_src > 0) conf += 0.6;
    if (ksu_src > 0) conf += 0.7;
    if (zero_size_system > 0) conf += 0.3;
    if (umount_marker > 0) conf += 0.4;
    if (conf > 0.95) conf = 0.95;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "mount_entries", lines);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "tmpfs_over_system", tmpfs_system);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "worker_source", worker_src);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "ksu_source", ksu_src);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "system_mount_size_zero", zero_size_system);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "data_adb_mount", umount_marker);
    rb_puts(&b, "}");
    rasp_emit(c, "ZYS-003", "Shamiko 挂载隔离特征", "zygisk", GRADE_STRONG, conf, hit, 1, raw,
              NULL);
}

/* ------------------------------------------------------------------ ZYS-004 */

static void check_lsposed(rasp_ctx_t *c)
{
    rasp_maps_stats_t st;
    if (rasp_maps_stats(&st) != 0) {
        rasp_emit(c, "ZYS-004", "LSPosed 方法 Hook 间接特征", "zygisk", GRADE_STRONG, 0.0, 0, 0,
                  NULL, "cannot read /proc/self/maps");
        return;
    }

    /* LSPosed 的 native 痕迹：模块 so 映射 / 可写可执行段 / ART 代码段可写 */
    int module_hit = 0;
    static rasp_map_t maps[512];
    int n = rasp_maps_load(maps, 512);
    char examples[192] = {0};
    for (int i = 0; i < n; i++) {
        if (strstr(maps[i].path, "lspd") || strstr(maps[i].path, "lsposed") ||
            strstr(maps[i].path, "edxp") || strstr(maps[i].path, "xposed") ||
            strstr(maps[i].path, "riru")) {
            module_hit++;
            if (examples[0] == '\0') {
                snprintf(examples, sizeof(examples), "%s", maps[i].path);
            }
        }
    }

    int hit = module_hit > 0 || st.rwx > 1 || st.art_writable > 0;
    double conf = 0.0;
    if (module_hit > 0) conf += 0.85;
    if (st.rwx > 1) conf += 0.45;
    if (st.art_writable > 0) conf += 0.6;
    if (conf > 0.95) conf = 0.95;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "module_mappings", module_hit);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "module_example", examples);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "rwx_segments", st.rwx);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "libart_code_writable", st.art_writable);
    rb_puts(&b, "}");
    rasp_emit(c, "ZYS-004", "LSPosed 方法 Hook 间接特征", "zygisk", GRADE_STRONG, conf, hit, 1,
              raw, NULL);
}

void rasp_check_zygisk(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2500);
    check_zygote_injection(c);
    if (!rasp_deadline_hit(c)) check_native_bridge(c);
    if (!rasp_deadline_hit(c)) check_shamiko(c);
    if (!rasp_deadline_hit(c)) check_lsposed(c);
}
