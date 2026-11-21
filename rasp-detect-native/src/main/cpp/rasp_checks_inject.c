/*
 * rasp_checks_inject.c —— 第 6 类：Ptrace / 内存映射 / 进程注入线索
 *
 * 检测项：
 *   INJ-001 进程内存映射异常匿名段检测【间接】
 *   INJ-002 ptrace 后门痕迹间接检测【强】
 *   INJ-003 系统库函数入口完整性校验【强】
 *   INJ-004 Dex 文件匿名内存加载检测【间接】
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ INJ-001 */

static void check_maps_anomaly(rasp_ctx_t *c)
{
    rasp_maps_stats_t st;
    if (rasp_maps_stats(&st) != 0) {
        rasp_emit(c, "INJ-001", "进程内存映射异常匿名段检测", "inject", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "cannot read /proc/self/maps");
        return;
    }
    int hit = st.rwx > 1 || st.anon_exec > 3 || st.big_anon_rw > 12;
    double conf = 0.0;
    if (st.rwx > 1) conf += 0.5;
    if (st.anon_exec > 3) conf += 0.3;
    if (st.big_anon_rw > 12) conf += 0.15;
    if (conf > 0.9) conf = 0.9;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "map_total", st.total);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "rwx_segments", st.rwx);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anon_exec_segments", st.anon_exec);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "big_anon_rw", st.big_anon_rw);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "deleted_exec", st.deleted_exec);
    rb_puts(&b, "}");
    rasp_emit(c, "INJ-001", "进程内存映射异常匿名段检测", "inject", GRADE_INDIRECT, conf, hit, 1,
              raw, NULL);
}

/* ------------------------------------------------------------------ INJ-002 */

static void check_tracer(rasp_ctx_t *c)
{
    static char status[8192];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "status", status, sizeof(status) - 1, &len, &err, &via) != 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", err);
        rasp_emit(c, "INJ-002", "ptrace 后门痕迹间接检测", "inject", GRADE_STRONG, 0.0, 0, 0, raw,
                  "cannot read /proc/self/status");
        return;
    }
    status[len] = '\0';

    char tracer[32] = {0}, state[16] = {0}, ppid_s[32] = {0};
    rasp_status_value(status, "TracerPid", tracer, sizeof(tracer));
    rasp_status_value(status, "State", state, sizeof(state));
    rasp_status_value(status, "PPid", ppid_s, sizeof(ppid_s));
    int tracer_pid = atoi(tracer);
    int traced_state = (state[0] == 't' || state[0] == 'T');

    /* 父进程若被调试，其子进程也可作为旁证 */
    int parent_traced = 0;
    char parent_tracer[64] = {0};
    int ppid = atoi(ppid_s);
    if (ppid > 1) {
        static char pstatus[8192];
        size_t plen = 0;
        if (rasp_read_proc((pid_t)ppid, "status", pstatus, sizeof(pstatus) - 1, &plen, &err,
                           &via) == 0) {
            pstatus[plen] = '\0';
            rasp_status_value(pstatus, "TracerPid", parent_tracer, sizeof(parent_tracer));
            parent_traced = atoi(parent_tracer) > 0;
        }
    }

    int hit = tracer_pid > 0 || traced_state || parent_traced;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "tracer_pid", tracer_pid);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "state", state);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "parent_pid", ppid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "parent_tracer", atoi(parent_tracer));
    rb_puts(&b, "}");
    rasp_emit(c, "INJ-002", "ptrace 后门痕迹间接检测", "inject", GRADE_STRONG,
              hit ? 0.95 : 0.0, hit, 1, raw, NULL);
}

/* ------------------------------------------------------------------ INJ-003 */

typedef struct {
    const char *module;
    const char *name;
    void *addr;
} fn_probe_t;

static void check_system_lib_entries(rasp_ctx_t *c)
{
    void *h = dlopen("libc.so", RTLD_NOW);
    if (h == NULL) h = dlopen("libc.so.6", RTLD_NOW);

    fn_probe_t probes[6];
    int np = 0;
    probes[np].module = "libc.so";
    probes[np].name = "dlsym";
    probes[np++].addr = (void *)dlsym(h ? h : RTLD_DEFAULT, "dlsym");
    probes[np].module = "libc.so";
    probes[np].name = "__system_property_get";
    probes[np++].addr = (void *)dlsym(h ? h : RTLD_DEFAULT, "__system_property_get");
    probes[np].module = "libc.so";
    probes[np].name = "pthread_create";
    probes[np++].addr = (void *)dlsym(h ? h : RTLD_DEFAULT, "pthread_create");
    probes[np].module = "libc.so";
    probes[np].name = "malloc";
    probes[np++].addr = (void *)dlsym(h ? h : RTLD_DEFAULT, "malloc");
    probes[np].module = "libart.so";
    probes[np].name = "JNI_GetCreatedJavaVMs";
    probes[np++].addr = (void *)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    probes[np].module = "libnativehelper.so";
    probes[np].name = "JNI_GetCreatedJavaVMs(nh)";
    probes[np++].addr = (void *)dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    if (h) dlclose(h);

    int checked = 0, suspicious = 0;
    char detail[640] = {0};
    for (int i = 0; i < np; i++) {
        if (probes[i].addr == NULL) continue;
        char d[192] = {0};
        int rc = rasp_check_function_entry(probes[i].addr, probes[i].module, d, sizeof(d));
        if (rc < 0) continue; /* 模块不在 maps 中，跳过 */
        checked++;
        size_t l = strlen(detail);
        snprintf(detail + l, sizeof(detail) - l, "%s:%s;", probes[i].name, d);
        if (rc > 0) suspicious++;
    }

    int hit = suspicious > 0;
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
    rasp_emit(c, "INJ-003", "系统库函数入口完整性校验", "inject", GRADE_STRONG,
              hit ? 0.9 : 0.0, hit, checked > 0, raw,
              checked > 0 ? NULL : "no probeable system library");
}

/* ------------------------------------------------------------------ INJ-004 */

static void check_anon_dex(rasp_ctx_t *c)
{
    static rasp_map_t maps[1024];
    int n = rasp_maps_load(maps, 1024);
    if (n <= 0) {
        rasp_emit(c, "INJ-004", "Dex 文件匿名内存加载检测", "inject", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "cannot read /proc/self/maps");
        return;
    }

    int anon_dex = 0, deleted_dex = 0, dex_total = 0;
    char examples[256] = {0};
    for (int i = 0; i < n; i++) {
        const char *p = maps[i].path;
        if (p[0] == '\0') continue;
        if (strstr(p, ".dex") == NULL && strstr(p, ".vdex") == NULL &&
            strstr(p, ".oat") == NULL) {
            continue;
        }
        dex_total++;
        if (strstr(p, "memfd:") != NULL || strncmp(p, "/memfd", 6) == 0) {
            anon_dex++;
        }
        if (strstr(p, "(deleted)") != NULL) deleted_dex++;
        if ((anon_dex || deleted_dex) && examples[0] == '\0') {
            snprintf(examples, sizeof(examples), "%s", p);
        }
    }

    int hit = anon_dex > 0 || deleted_dex > 0;
    double conf = 0.0;
    if (anon_dex > 0) conf += 0.65;
    if (deleted_dex > 0) conf += 0.5;
    if (conf > 0.9) conf = 0.9;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "dex_mappings", dex_total);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anon_dex", anon_dex);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "deleted_dex", deleted_dex);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "example", examples);
    rb_puts(&b, "}");
    rasp_emit(c, "INJ-004", "Dex 文件匿名内存加载检测", "inject", GRADE_INDIRECT, conf, hit, 1,
              raw, NULL);
}

void rasp_check_inject(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2000);
    check_maps_anomaly(c);
    if (!rasp_deadline_hit(c)) check_tracer(c);
    if (!rasp_deadline_hit(c)) check_system_lib_entries(c);
    if (!rasp_deadline_hit(c)) check_anon_dex(c);
}
