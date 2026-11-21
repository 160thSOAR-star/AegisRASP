/*
 * rasp_jni.c —— JNI 接口层（Native 核心的唯一入口）
 *
 * 对外暴露的 Kotlin API（见 RaspNative.kt）：
 *   runDetect(configJson, whitelistJson, sink) -> 报告 JSON
 *   submitEvidence(json)      —— Java 层补充证据（包列表多路径校验等）
 *   cancelDetect()            —— 中断当前检测
 *
 * 所有方法通过 RegisterNatives 显式注册，符号不导出（fvisibility=hidden）。
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <jni.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/system_properties.h>

static JavaVM *g_vm;
static const void **g_env_table;
static volatile int g_cancel;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_pending[4][2048];
static int g_pending_n;

typedef struct {
    JNIEnv *env;
    jobject sink;
    jmethodID on_evidence;
} sink_ctx_t;

/* ------------------------------------------------------------------ 反 Hook 支撑 */

int rasp_cancelled(void)
{
    return g_cancel != 0;
}

/* 地址是否位于可执行映射中（用于 JNI 函数表校验） */
static int addr_executable(uint64_t addr)
{
    static rasp_map_t maps[512];
    int n = rasp_maps_load(maps, 512);
    if (n <= 0) return -1;
    for (int i = 0; i < n; i++) {
        if (addr >= maps[i].start && addr < maps[i].end) {
            return maps[i].perms[2] == 'x';
        }
    }
    return 0;
}

int rasp_jni_table_verify(char *detail, size_t cap)
{
    if (detail == NULL || cap == 0) return 0;
    detail[0] = '\0';
    if (g_vm == NULL) {
        snprintf(detail, cap, "no JavaVM captured");
        return 0;
    }
    JNIEnv *env = NULL;
    if ((*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        snprintf(detail, cap, "GetEnv failed");
        return 0;
    }
    const void **table = (const void **)(*(void ***)env);
    int tampered = 0;
    if (table != g_env_table) {
        tampered++;
        snprintf(detail, cap, "JNINativeInterface table pointer changed");
    }

    /* 关键槽位（ABI 固定）：4=GetVersion 6=FindClass 31=GetObjectClass 228=GetJavaVM */
    const int slots[] = {4, 6, 31};
    for (int i = 0; i < 3; i++) {
        void *fn = (void *)table[slots[i]];
        if (fn == NULL) continue;
        int ex = addr_executable((uint64_t)(uintptr_t)fn);
        if (ex == 0) {
            tampered++;
            size_t l = strlen(detail);
            snprintf(detail + l, cap - l, "slot %d points outside executable map", slots[i]);
        }
    }
    return tampered;
}

/* ------------------------------------------------------------------ 证据流式回调 */

static void jni_evidence_sink(void *ud, const char *json_line)
{
    sink_ctx_t *sc = (sink_ctx_t *)ud;
    if (sc == NULL || sc->env == NULL || sc->sink == NULL || sc->on_evidence == NULL) return;
    JNIEnv *env = sc->env;
    jstring s = (*env)->NewStringUTF(env, json_line);
    if (s == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return;
    }
    (*env)->CallVoidMethod(env, sc->sink, sc->on_evidence, s);
    (*env)->DeleteLocalRef(env, s);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
}

/* ------------------------------------------------------------------ 检测入口 */

static jstring build_jstring(JNIEnv *env, const char *s)
{
    size_t len = strlen(s);
    /* NewStringUTF 要求 modified UTF-8；本项目输出的文本仅为 ASCII 与 BMP 汉字，安全 */
    if (len > 240000) {
        char tiny[512];
        snprintf(tiny, sizeof(tiny),
                 "{\"schema\":1,\"score\":0,\"level\":\"safe\",\"error\":\"report too large\","
                 "\"items\":[]}");
        return (*env)->NewStringUTF(env, tiny);
    }
    return (*env)->NewStringUTF(env, s);
}

static int json_flag(const char *json, const char *key, int def)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":true", key);
    if (strstr(json, pat) != NULL) return 1;
    snprintf(pat, sizeof(pat), "\"%s\":false", key);
    if (strstr(json, pat) != NULL) return 0;
    return def;
}

static jstring jni_run_detect(JNIEnv *env, jclass clazz, jstring config, jstring whitelist,
                             jstring weights, jobject sink)
{
    (void)clazz;
    g_cancel = 0;

    static rasp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.self_pid = rasp_raw_getpid();
    ctx.self_uid = rasp_raw_getuid();
    ctx.start_ms = rasp_now_ms();
    ctx.fast_mode = 0;
    ctx.sandbox_enabled = 1;
    ctx.whitelist_enabled = 1;
    ctx.probe_ready = 0;

    const char *cfg = config ? (*env)->GetStringUTFChars(env, config, NULL) : NULL;
    if (cfg != NULL) {
        ctx.fast_mode = json_flag(cfg, "fastMode", 0);
        ctx.sandbox_enabled = json_flag(cfg, "sandbox", 1);
        ctx.whitelist_enabled = json_flag(cfg, "whitelist", 1);
        rasp_extract_array(cfg, "disabled", ctx.disabled_ids, sizeof(ctx.disabled_ids));
        (*env)->ReleaseStringUTFChars(env, config, cfg);
    }

    const char *ws = weights ? (*env)->GetStringUTFChars(env, weights, NULL) : NULL;
    if (ws != NULL) {
        snprintf(ctx.weight_spec, sizeof(ctx.weight_spec), "%s", ws);
        (*env)->ReleaseStringUTFChars(env, weights, ws);
    }

    const char *wl = whitelist ? (*env)->GetStringUTFChars(env, whitelist, NULL) : NULL;
    if (wl != NULL) {
        rasp_extract_array(wl, "mounts", ctx.wl_mount, sizeof(ctx.wl_mount));
        rasp_extract_array(wl, "processes", ctx.wl_proc, sizeof(ctx.wl_proc));
        rasp_extract_array(wl, "properties", ctx.wl_prop, sizeof(ctx.wl_prop));
        rasp_extract_array(wl, "kernel", ctx.wl_kernel, sizeof(ctx.wl_kernel));
        rasp_extract_array(wl, "oem", ctx.wl_oem, sizeof(ctx.wl_oem));
        (*env)->ReleaseStringUTFChars(env, whitelist, wl);
    }

    sink_ctx_t sc;
    memset(&sc, 0, sizeof(sc));
    sc.env = env;
    sc.sink = sink;
    if (sink != NULL) {
        /* 直接在接口类型上取方法 ID：Kotlin SAM 转换生成的实现类与接口都适用 */
        jclass sink_iface = (*env)->FindClass(env, "com/rasp/detect/RaspNative$EvidenceSink");
        if (sink_iface != NULL) {
            sc.on_evidence =
                (*env)->GetMethodID(env, sink_iface, "onEvidence", "(Ljava/lang/String;)V");
            (*env)->DeleteLocalRef(env, sink_iface);
        }
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            sc.on_evidence = NULL;
        }
        if (sc.on_evidence != NULL) {
            ctx.sink = jni_evidence_sink;
            ctx.sink_ud = &sc;
        }
    }

    /* Java 层提交的补充证据优先输出 */
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_pending_n; i++) {
        (void)rasp_ingest_external(&ctx, g_pending[i]);
    }
    g_pending_n = 0;
    pthread_mutex_unlock(&g_lock);

    /* 分级调度：低开销项全量，高开销项仅在非 fast 模式执行 */
    rasp_check_mount(&ctx);
    if (!rasp_cancelled()) rasp_check_ksu(&ctx);
    if (!rasp_cancelled()) rasp_check_kernel_trace(&ctx);
    if (!rasp_cancelled()) rasp_check_bpf(&ctx);
    if (!rasp_cancelled()) rasp_check_zygisk(&ctx);
    if (!rasp_cancelled()) rasp_check_inject(&ctx);
    if (!rasp_cancelled()) rasp_check_security(&ctx);
    if (!rasp_cancelled()) rasp_check_extra(&ctx);
    if (!rasp_cancelled() && ctx.sandbox_enabled) rasp_check_sandbox(&ctx);
    rasp_check_antihook(&ctx);

    static char report[256 * 1024];
    rasp_build_report_json(&ctx, report, sizeof(report));
    ctx.sink = NULL;
    sc.sink = NULL;
    return build_jstring(env, report);
}

static void jni_submit(JNIEnv *env, jclass clazz, jstring json)
{
    (void)clazz;
    if (json == NULL) return;
    const char *s = (*env)->GetStringUTFChars(env, json, NULL);
    if (s == NULL) return;
    pthread_mutex_lock(&g_lock);
    if (g_pending_n < 4) {
        snprintf(g_pending[g_pending_n], sizeof(g_pending[0]), "%s", s);
        g_pending_n++;
    }
    pthread_mutex_unlock(&g_lock);
    (*env)->ReleaseStringUTFChars(env, json, s);
}

static void jni_cancel(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    g_cancel = 1;
}

static jstring jni_version(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    return (*env)->NewStringUTF(env, "aegis-rasp/1.0.1 (native, api35)");
}

/* 供 Java 层做「属性区双路径一致性」比对（ZYS-008）：直接读属性区，不经过 Java SystemProperties */
static jstring jni_read_property(JNIEnv *env, jclass clazz, jstring key)
{
    (void)clazz;
    if (key == NULL) return NULL;
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    if (k == NULL) return NULL;
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(k, value);
    (*env)->ReleaseStringUTFChars(env, key, k);
    return (*env)->NewStringUTF(env, value);
}

/* ------------------------------------------------------------------ 注册 */

static const JNINativeMethod g_methods[] = {
    {"runDetect", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/rasp/detect/RaspNative$EvidenceSink;)Ljava/lang/String;",
     (void *)jni_run_detect},
    {"submitEvidence", "(Ljava/lang/String;)V", (void *)jni_submit},
    {"cancelDetect", "()V", (void *)jni_cancel},
    {"nativeVersion", "()Ljava/lang/String;", (void *)jni_version},
    {"readProperty", "(Ljava/lang/String;)Ljava/lang/String;", (void *)jni_read_property},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    g_vm = vm;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    g_env_table = (const void **)(*(void ***)env);

    /* 记录自身热代码初始指纹，供 AHK-003 运行时比对 */
    rasp_ahk_snapshot();

    jclass cls = (*env)->FindClass(env, "com/rasp/detect/RaspNative");
    if (cls == NULL) return JNI_ERR;
    if ((*env)->RegisterNatives(env, cls, g_methods,
                                (jint)(sizeof(g_methods) / sizeof(g_methods[0]))) != JNI_OK) {
        (*env)->DeleteLocalRef(env, cls);
        return JNI_ERR;
    }
    (*env)->DeleteLocalRef(env, cls);
    return JNI_VERSION_1_6;
}
