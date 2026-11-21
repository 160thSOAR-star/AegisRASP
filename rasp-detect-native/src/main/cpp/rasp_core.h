/*
 * rasp_core.h —— RASP 检测核心公共定义
 *
 * 设计约束（见《生成要求》第 0 章）：
 *  - 全部逻辑运行在普通应用进程（untrusted_app / 沙箱子进程），不使用任何 root 权限；
 *  - 所有敏感读取走直调 syscall 引擎（绕过 bionic 包装，规避用户态 inline hook）；
 *  - 仅采集证据，不修改、不绕过、不攻击任何环境。
 */
#ifndef RASP_CORE_H
#define RASP_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RASP_MAX_EVIDENCE 48
#define RASP_RAW_MAX 2560
#define RASP_ERR_MAX 192

/* 证据等级：强证据 / 间接证据 / 弱线索 */
typedef enum {
    GRADE_WEAK = 0,
    GRADE_INDIRECT = 1,
    GRADE_STRONG = 2
} rasp_grade_t;

typedef struct {
    char id[24];
    char name[112];
    char category[16];
    rasp_grade_t grade;
    double confidence; /* 0.0 - 1.0 */
    int hit;           /* 1 = 命中（发现异常），0 = 未命中 / 不可用 */
    int available;     /* 1 = 本次检测实际执行成功，0 = 环境受限不可用 */
    char raw[RASP_RAW_MAX];
    char error[RASP_ERR_MAX];
    long cost_ms;
    long long ts_ms;
} rasp_evidence_t;

typedef struct rasp_ctx rasp_ctx_t;

/* 检测上下文 */
struct rasp_ctx {
    pid_t self_pid;
    uid_t self_uid;
    long long start_ms;

    long long module_deadline_ms; /* 当前检测项超时熔断时间点（monotonic ms） */

    int fast_mode;        /* 1 = 仅执行低开销项（分级调度） */
    int sandbox_enabled;  /* 是否启用 clone3 沙箱 */
    int whitelist_enabled;
    int probe_ready;      /* 可选内核探针是否已授权部署（普通环境恒为 0） */

    /* 白名单（空格分隔片段，来自 assets/whitelist_default.json） */
    char wl_mount[768];
    char wl_proc[768];
    char wl_prop[1024];
    char wl_kernel[768];
    char wl_oem[768];

    /* 自定义权重（"ID=权重;"）与被禁用的检测项（空格分隔 ID） */
    char weight_spec[1024];
    char disabled_ids[768];

    /* 流式回调：每产生一条证据即以单行 JSON 推给 Java 层 */
    void (*sink)(void *ud, const char *json_line);
    void *sink_ud;

    /* 证据聚合 */
    rasp_evidence_t items[RASP_MAX_EVIDENCE];
    int item_count;
    int anti_hook_hit; /* 反 Hook 自校验被篡改 => 直接高风险 */

    /* 沙箱共享内存 */
    void *shm;
    size_t shm_size;
    int shm_ready;
};

/* ---------- 工具 ---------- */
long long rasp_now_ms(void);
uint64_t rasp_mono_ns(void);
uint64_t rasp_hash64(const void *data, size_t len);
int rasp_deadline_hit(rasp_ctx_t *c);
void rasp_ctx_set_budget(rasp_ctx_t *c, long long budget_ms);
int rasp_emit(rasp_ctx_t *c, const char *id, const char *name, const char *category,
              rasp_grade_t grade, double conf, int hit, int available,
              const char *raw_json, const char *error);
int rasp_whitelisted(rasp_ctx_t *c, const char *needle,
                     const char *w0, const char *w1, const char *w2,
                     const char *w3, const char *w4);

/* 简易动态字符串（容量足够，越界即截断并置位 trunc） */
typedef struct {
    char *buf;
    size_t cap;
    size_t len;
    int trunc;
} rasp_buf_t;

void rb_init(rasp_buf_t *b, char *buf, size_t cap);
void rb_puts(rasp_buf_t *b, const char *s);
void rb_printf(rasp_buf_t *b, const char *fmt, ...);
void rb_json_kv_str(rasp_buf_t *b, const char *k, const char *v);
void rb_json_kv_int(rasp_buf_t *b, const char *k, long long v);
void rb_json_kv_double(rasp_buf_t *b, const char *k, double v);
void rb_json_kv_bool(rasp_buf_t *b, const char *k, int v);
void rb_json_kv_escaped(rasp_buf_t *b, const char *k, const char *v);
void rb_json_str_value(rasp_buf_t *b, const char *v);

/* 各检测模块入口 */
void rasp_check_mount(rasp_ctx_t *c);
void rasp_check_ksu(rasp_ctx_t *c);
void rasp_check_kernel_trace(rasp_ctx_t *c);
void rasp_check_bpf(rasp_ctx_t *c);
void rasp_check_zygisk(rasp_ctx_t *c);
void rasp_check_inject(rasp_ctx_t *c);
void rasp_check_security(rasp_ctx_t *c);
void rasp_check_extra(rasp_ctx_t *c);
void rasp_check_antihook(rasp_ctx_t *c);
void rasp_check_sandbox(rasp_ctx_t *c);

/* 反 Hook 自校验（rasp_checks_antihook.c / rasp_jni.c） */
void rasp_ahk_snapshot(void);
int rasp_cancelled(void);
int rasp_jni_table_verify(char *detail, size_t cap);

/* 打分与汇总 */
int rasp_score_compute(rasp_ctx_t *c, double *out_confidence, const char **out_level);
void rasp_build_report_json(rasp_ctx_t *c, char *out, size_t cap);

/* 外部（Java 层）补充证据入口，例如包列表多路径校验 */
int rasp_ingest_external(rasp_ctx_t *c, const char *json);

/* ---------- 通用读取/解析（rasp_util.c） ---------- */
int rasp_read_all_fd(int fd, char *buf, size_t cap, size_t *out_len);
int rasp_read_file_raw(const char *path, char *buf, size_t cap, size_t *out_len);
int rasp_read_file_libc(const char *path, char *buf, size_t cap, size_t *out_len);
int rasp_read_proc(pid_t pid, const char *name, char *buf, size_t cap, size_t *out_len,
                   int *out_errno, int *out_via_pidfd);
void rasp_extract_array(const char *json, const char *key, char *dst, size_t cap);
const char *rasp_strstr(const char *hay, const char *needle);
int rasp_contains_ci(const char *hay, const char *needle);
int rasp_count_lines(const char *s);
int rasp_field(const char *line, int idx, char *out, size_t cap);
int rasp_status_value(const char *buf, const char *key, char *out, size_t cap);

/* 有界进程枚举 */
typedef struct {
    pid_t pid;
    char cmdline[192];
    char comm[64];
    int readable;
} rasp_proc_entry_t;

int rasp_scan_procs(rasp_proc_entry_t *out, int cap, int max_scan);
pid_t rasp_find_proc_pid(const char *name, int max_scan);

#endif /* RASP_CORE_H */
