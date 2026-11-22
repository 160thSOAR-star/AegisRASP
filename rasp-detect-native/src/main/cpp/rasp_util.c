/*
 * rasp_util.c —— 基础工具：时间、哈希、JSON 缓冲、文件/进程读取、白名单、证据聚合
 */
#include "rasp_core.h"
#include "rasp_syscall.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------ 时间/哈希 */

long long rasp_now_ms(void)
{
    struct rasp_timespec ts;
    if (rasp_raw_clock_gettime(RASP_CLOCK_REALTIME, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

uint64_t rasp_mono_ns(void)
{
    struct rasp_timespec ts;
    if (rasp_raw_clock_gettime(RASP_CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static long long mono_ms(void)
{
    return (long long)(rasp_mono_ns() / 1000000ULL);
}

uint64_t rasp_hash64(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 1469598103934665603ULL; /* FNV-1a 64 */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void rasp_ctx_set_budget(rasp_ctx_t *c, long long budget_ms)
{
    if (c == NULL) return;
    c->module_deadline_ms = mono_ms() + (budget_ms > 0 ? budget_ms : 1);
}

int rasp_deadline_hit(rasp_ctx_t *c)
{
    if (rasp_cancelled()) return 1;
    if (c == NULL || c->module_deadline_ms <= 0) return 0;
    return mono_ms() >= c->module_deadline_ms;
}

/* ------------------------------------------------------------------ 缓冲/JSON */

void rb_init(rasp_buf_t *b, char *buf, size_t cap)
{
    b->buf = buf;
    b->cap = cap;
    b->len = 0;
    b->trunc = 0;
    if (cap > 0) buf[0] = '\0';
}

void rb_puts(rasp_buf_t *b, const char *s)
{
    if (b == NULL || b->cap == 0 || s == NULL) return;
    size_t n = strlen(s);
    size_t room = b->cap - 1 - b->len;
    if (n > room) {
        n = room;
        b->trunc = 1;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

void rb_printf(rasp_buf_t *b, const char *fmt, ...)
{
    if (b == NULL || b->cap == 0 || fmt == NULL) return;
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof(tmp)) {
        b->trunc = 1;
        tmp[sizeof(tmp) - 1] = '\0';
    }
    rb_puts(b, tmp);
}

/*
 * JSON 字符串转义 + UTF-8 合法性校验。
 *
 * 关键点：JNI 的 NewStringUTF 只接受 modified UTF-8，遇到 4 字节序列或非法字节会
 * 直接让 ART 中止（表现为"点一下闪退"）。而证据里的进程名、路径、属性值来自内核，
 * 不保证是合法 UTF-8。因此这里在转义阶段就把非法字节 / 4 字节序列替换成 '?'，
 * 保证送进 JVM 的文本永远安全（中文为 3 字节，正常保留）。
 */
static void rb_json_escape(rasp_buf_t *b, const char *s)
{
    if (s == NULL) {
        rb_puts(b, "\"\"");
        return;
    }
    rb_puts(b, "\"");
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        if (c == '"') {
            rb_puts(b, "\\\"");
            p++;
        } else if (c == '\\') {
            rb_puts(b, "\\\\");
            p++;
        } else if (c == '\n') {
            rb_puts(b, "\\n");
            p++;
        } else if (c == '\r') {
            rb_puts(b, "\\r");
            p++;
        } else if (c == '\t') {
            rb_puts(b, "\\t");
            p++;
        } else if (c < 0x20) {
            char esc[8];
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            rb_puts(b, esc);
            p++;
        } else if (c < 0x80) {
            char one[2] = {(char)c, '\0'};
            rb_puts(b, one);
            p++;
        } else if ((c & 0xE0) == 0xC0 && p[1] != '\0' && (p[1] & 0xC0) == 0x80) {
            char two[3] = {(char)p[0], (char)p[1], '\0'};
            rb_puts(b, two);
            p += 2;
        } else if ((c & 0xF0) == 0xE0 && p[1] != '\0' && p[2] != '\0' &&
                   (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
            char three[4] = {(char)p[0], (char)p[1], (char)p[2], '\0'};
            rb_puts(b, three);
            p += 3;
        } else {
            /* 4 字节序列、孤立续字节、截断序列：统一替换，避免 JNI 中止 */
            rb_puts(b, "?");
            p++;
        }
    }
    rb_puts(b, "\"");
}

void rb_json_str_value(rasp_buf_t *b, const char *v)
{
    rb_json_escape(b, v);
}

void rb_json_kv_str(rasp_buf_t *b, const char *k, const char *v)
{
    rb_json_escape(b, k);
    rb_puts(b, ":");
    rb_json_escape(b, v);
}

void rb_json_kv_escaped(rasp_buf_t *b, const char *k, const char *v)
{
    rb_json_kv_str(b, k, v);
}

void rb_json_kv_int(rasp_buf_t *b, const char *k, long long v)
{
    rb_json_escape(b, k);
    rb_printf(b, ":%lld", v);
}

void rb_json_kv_double(rasp_buf_t *b, const char *k, double v)
{
    rb_json_escape(b, k);
    rb_printf(b, ":%.3f", v);
}

void rb_json_kv_bool(rasp_buf_t *b, const char *k, int v)
{
    rb_json_escape(b, k);
    rb_puts(b, v ? ":true" : ":false");
}

/* ------------------------------------------------------------------ 文件读取 */

int rasp_read_all_fd(int fd, char *buf, size_t cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (buf == NULL || cap == 0) return -1;
    size_t total = 0;
    while (total + 1 < cap) {
        long n = rasp_raw_read(fd, buf + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    if (out_len) *out_len = total;
    return 0;
}

int rasp_read_file_raw(const char *path, char *buf, size_t cap, size_t *out_len)
{
    int fd = rasp_raw_open(path, RASP_O_RDONLY | RASP_O_CLOEXEC, 0);
    if (fd < 0) return -1;
    int rc = rasp_read_all_fd(fd, buf, cap, out_len);
    int saved = errno;
    rasp_raw_close(fd);
    errno = saved;
    return rc;
}

int rasp_read_file_libc(const char *path, char *buf, size_t cap, size_t *out_len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    if (out_len) *out_len = total;
    close(fd);
    return 0;
}

/*
 * 通过 pidfd 打开目标进程的 procfs 文件：
 *   openat(pidfd, name) 与 /proc/<pid>/name 是同一份内核视图；
 *   优先 pidfd，失败再回退 /proc 路径，二者结果不一致本身即为线索。
 */
int rasp_read_proc(pid_t pid, const char *name, char *buf, size_t cap, size_t *out_len,
                   int *out_errno, int *out_via_pidfd)
{
    if (out_errno) *out_errno = 0;
    if (out_via_pidfd) *out_via_pidfd = 0;

    /* pidfd_open 在部分 ROM 的 seccomp 策略下会触发致命信号；只有探测通过才使用 */
    int pfd = -1;
    if (rasp_pidfd_enabled()) {
        pfd = rasp_pidfd_open_compat(pid);
    } else {
        errno = ENOSYS;
    }
    if (pfd >= 0) {
        int fd = rasp_raw_openat(pfd, name, RASP_O_RDONLY | RASP_O_CLOEXEC, 0);
        int saved = errno;
        if (fd >= 0) {
            int rc = rasp_read_all_fd(fd, buf, cap, out_len);
            saved = errno;
            rasp_raw_close(fd);
            rasp_raw_close(pfd);
            if (rc == 0) {
                if (out_via_pidfd) *out_via_pidfd = 1;
                return 0;
            }
            if (out_errno) *out_errno = saved;
            return -1;
        }
        rasp_raw_close(pfd);
        if (out_errno) *out_errno = saved;
    } else {
        if (out_errno) *out_errno = errno;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, name);
    int rc = rasp_read_file_raw(path, buf, cap, out_len);
    if (rc != 0) {
        if (out_errno) *out_errno = errno;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ 字符串工具 */

const char *rasp_strstr(const char *hay, const char *needle)
{
    if (hay == NULL || needle == NULL) return NULL;
    return strstr(hay, needle);
}

int rasp_contains_ci(const char *hay, const char *needle)
{
    if (hay == NULL || needle == NULL) return 0;
    size_t nl = strlen(needle);
    if (nl == 0) return 0;
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nl) return 1;
    }
    return 0;
}

int rasp_count_lines(const char *s)
{
    if (s == NULL) return 0;
    int n = 0;
    for (const char *p = s; *p; p++) {
        if (*p == '\n') n++;
    }
    if (s[0] != '\0' && s[strlen(s) - 1] != '\n') n++;
    return n;
}

/* 取一行中第 idx 个以空格分隔的字段（mountinfo / status 解析用） */
int rasp_field(const char *line, int idx, char *out, size_t cap)
{
    if (line == NULL || out == NULL || cap == 0) return -1;
    out[0] = '\0';
    int cur = 0;
    const char *p = line;
    while (*p == ' ') p++;
    while (*p) {
        const char *start = p;
        while (*p && *p != ' ' && *p != '\n') p++;
        if (cur == idx) {
            size_t n = (size_t)(p - start);
            if (n >= cap) n = cap - 1;
            memcpy(out, start, n);
            out[n] = '\0';
            return 0;
        }
        cur++;
        while (*p == ' ') p++;
    }
    return -1;
}

/* 从 /proc/<pid>/status 风格的 "Key:\tvalue" 文本中取一行的值 */
int rasp_status_value(const char *buf, const char *key, char *out, size_t cap)
{
    if (buf == NULL || key == NULL || out == NULL || cap == 0) return -1;
    out[0] = '\0';
    size_t kl = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (strncmp(p, key, kl) == 0 && p[kl] == ':') {
            const char *v = p + kl + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t i = 0;
            while (v[i] && v[i] != '\n' && i + 1 < cap) {
                out[i] = v[i];
                i++;
            }
            out[i] = '\0';
            return 0;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return -1;
}

/* ------------------------------------------------------------------ 进程枚举 */

/*
 * 有界进程扫描：只读 /proc 目录项 + cmdline（Android 上 cmdline 跨域可读），
 * 扫描上限由调用方给出，禁止全量遍历（性能约束）。
 */
int rasp_scan_procs(rasp_proc_entry_t *out, int cap, int max_scan)
{
    if (out == NULL || cap <= 0) return -1;
    int fd = rasp_raw_open("/proc", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC, 0);
    if (fd < 0) return -1;

    char buf[8192];
    int n = 0, scanned = 0;
    for (;;) {
        long got = rasp_raw_getdents64(fd, buf, sizeof(buf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(buf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            pid_t pid = (pid_t)atoi(d->d_name);
            if (pid <= 0) continue;
            if (++scanned > max_scan) {
                rasp_raw_close(fd);
                return n;
            }
            if (n >= cap) {
                rasp_raw_close(fd);
                return n;
            }
            rasp_proc_entry_t *e = &out[n];
            memset(e, 0, sizeof(*e));
            e->pid = pid;

            int err = 0, via = 0;
            size_t clen = 0;
            if (rasp_read_proc(pid, "cmdline", e->cmdline, sizeof(e->cmdline) - 1, &clen, &err,
                               &via) == 0) {
                e->cmdline[clen] = '\0';
                /* 多参数字符串化：把 \0 换成空格，便于匹配 */
                for (size_t i = 0; i + 1 < clen; i++) {
                    if (e->cmdline[i] == '\0') e->cmdline[i] = ' ';
                }
                e->readable = 1;
            }
            size_t commlen = 0;
            if (rasp_read_proc(pid, "comm", e->comm, sizeof(e->comm) - 1, &commlen, &err, &via) ==
                0) {
                e->comm[commlen] = '\0';
                while (commlen > 0 &&
                       (e->comm[commlen - 1] == '\n' || e->comm[commlen - 1] == '\r')) {
                    e->comm[--commlen] = '\0';
                }
            }
            n++;
        }
    }
    rasp_raw_close(fd);
    return n;
}

pid_t rasp_find_proc_pid(const char *name, int max_scan)
{
    static rasp_proc_entry_t entries[512];
    int n = rasp_scan_procs(entries, 512, max_scan);
    if (n <= 0) return -1;
    for (int i = 0; i < n; i++) {
        if (strcmp(entries[i].comm, name) == 0 || strcmp(entries[i].cmdline, name) == 0) {
            return entries[i].pid;
        }
    }
    for (int i = 0; i < n; i++) {
        if (entries[i].cmdline[0] && strstr(entries[i].cmdline, name) != NULL) {
            return entries[i].pid;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ 白名单 */

/* 多个片段之间用 ';' 分隔，保证 "overlay on /system_ext" 这类多词条目不被拆散 */
static void append_token(char *dst, size_t cap, const char *tok, size_t toklen)
{
    size_t cur = strlen(dst);
    if (cur + toklen + 2 >= cap) return;
    if (cur > 0) {
        dst[cur++] = ';';
        dst[cur] = '\0';
    }
    memcpy(dst + cur, tok, toklen);
    dst[cur + toklen] = '\0';
}

/*
 * 极简 JSON 数组提取：找到 "key" 后紧跟的 '[' 与 ']' 之间的带引号字符串，
 * 拼成空格分隔的片段表。native 层不引入第三方 JSON 库。
 */
void rasp_extract_array(const char *json, const char *key, char *dst, size_t cap)
{
    if (json == NULL || key == NULL || dst == NULL || cap == 0) return;
    dst[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (p == NULL) return;
    p = strchr(p + strlen(pat), '[');
    if (p == NULL) return;
    p++;
    while (*p && *p != ']') {
        if (*p == '"') {
            p++;
            const char *start = p;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            size_t n = (size_t)(p - start);
            if (n > 0 && n < 160) append_token(dst, cap, start, n);
            if (*p == '"') p++;
            continue;
        }
        p++;
    }
}

int rasp_whitelisted(rasp_ctx_t *c, const char *needle,
                     const char *w0, const char *w1, const char *w2,
                     const char *w3, const char *w4)
{
    if (c == NULL || !c->whitelist_enabled || needle == NULL || needle[0] == '\0') return 0;
    const char *pools[5] = {w0, w1, w2, w3, w4};
    for (int i = 0; i < 5; i++) {
        if (pools[i] && pools[i][0] && strstr(pools[i], needle) != NULL) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ 证据聚合 */

static const char *grade_name(rasp_grade_t g)
{
    switch (g) {
    case GRADE_STRONG: return "strong";
    case GRADE_INDIRECT: return "indirect";
    default: return "weak";
    }
}

int rasp_emit(rasp_ctx_t *c, const char *id, const char *name, const char *category,
              rasp_grade_t grade, double conf, int hit, int available,
              const char *raw_json, const char *error)
{
    if (c == NULL || id == NULL) return -1;
    if (c->item_count >= RASP_MAX_EVIDENCE) return -1;
    /* 设置页可关闭单个检测项：被关闭的项完全不参与采集与打分 */
    if (c->disabled_ids[0] != '\0') {
        const char *p = c->disabled_ids;
        size_t idlen = strlen(id);
        while (*p) {
            const char *sp = strchr(p, ';');
            size_t n = sp ? (size_t)(sp - p) : strlen(p);
            if (n == idlen && strncmp(p, id, n) == 0) return 0;
            if (!sp) break;
            p = sp + 1;
        }
    }
    if (conf < 0.0) conf = 0.0;
    if (conf > 1.0) conf = 1.0;

    rasp_evidence_t *e = &c->items[c->item_count];
    memset(e, 0, sizeof(*e));
    snprintf(e->id, sizeof(e->id), "%s", id);
    snprintf(e->name, sizeof(e->name), "%s", name ? name : "");
    snprintf(e->category, sizeof(e->category), "%s", category ? category : "");
    e->grade = grade;
    e->confidence = hit ? conf : 0.0;
    e->hit = hit ? 1 : 0;
    e->available = available ? 1 : 0;
    e->ts_ms = rasp_now_ms();
    if (raw_json) snprintf(e->raw, sizeof(e->raw), "%s", raw_json);
    if (error) snprintf(e->error, sizeof(e->error), "%s", error);

    c->item_count++;

    /* 流式推送：一条证据一行 JSON */
    if (c->sink) {
        static char line[RASP_RAW_MAX + 1024];
        rasp_buf_t b;
        rb_init(&b, line, sizeof(line));
        rb_puts(&b, "{");
        rb_json_kv_str(&b, "id", e->id);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "name", e->name);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "category", e->category);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "grade", grade_name(e->grade));
        rb_puts(&b, ",");
        rb_json_kv_double(&b, "confidence", e->hit ? e->confidence : 0.0);
        rb_puts(&b, ",");
        rb_json_kv_bool(&b, "hit", e->hit);
        rb_puts(&b, ",");
        rb_json_kv_bool(&b, "available", e->available);
        rb_puts(&b, ",");
        rb_puts(&b, "\"raw\":");
        if (e->raw[0] == '{' || e->raw[0] == '[') rb_puts(&b, e->raw);
        else rb_json_str_value(&b, e->raw);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "error", e->error);
        rb_puts(&b, ",");
        rb_json_kv_int(&b, "timestamp", e->ts_ms);
        rb_puts(&b, "}");
        c->sink(c->sink_ud, b.buf);
    }
    return 0;
}

/* ------------------------------------------------------------------ 外部证据注入 */

static int json_get_str(const char *json, const char *key, char *out, size_t cap)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (p == NULL) return -1;
    p = strchr(p + strlen(pat), ':');
    if (p == NULL) return -1;
    p++;
    while (*p == ' ') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) {
            p++;
            out[i++] = *p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
    return 0;
}

static int json_get_num(const char *json, const char *key, double *out)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (p == NULL) return -1;
    p = strchr(p + strlen(pat), ':');
    if (p == NULL) return -1;
    *out = strtod(p + 1, NULL);
    return 0;
}

int rasp_ingest_external(rasp_ctx_t *c, const char *json)
{
    if (c == NULL || json == NULL) return -1;
    char id[24] = {0}, name[112] = {0}, cat[16] = {0}, grade[16] = {0};
    char raw[1024] = {0};
    double conf = 0.0;
    if (json_get_str(json, "id", id, sizeof(id)) != 0) return -1;
    json_get_str(json, "name", name, sizeof(name));
    json_get_str(json, "category", cat, sizeof(cat));
    json_get_str(json, "grade", grade, sizeof(grade));
    json_get_str(json, "raw", raw, sizeof(raw));
    json_get_num(json, "confidence", &conf);
    int hit = strstr(json, "\"hit\":true") != NULL;
    int avail = strstr(json, "\"available\":false") == NULL;

    rasp_grade_t g = GRADE_WEAK;
    if (strcmp(grade, "strong") == 0) g = GRADE_STRONG;
    else if (strcmp(grade, "indirect") == 0) g = GRADE_INDIRECT;

    /* 外部证据的 raw 是字符串，包成对象便于报告统一渲染 */
    static char raw_obj[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw_obj, sizeof(raw_obj));
    rb_puts(&b, "{\"source\":\"java-layer\",\"detail\":");
    rb_json_str_value(&b, raw);
    rb_puts(&b, "}");
    return rasp_emit(c, id, name, cat, g, conf, hit, avail, raw_obj, NULL);
}
