/*
 * rasp_score.c —— ⑥ 加权打分聚合模型 + 报告序列化
 *
 * 权重：强证据 30 / 间接证据 10 / 弱线索 3，乘以检测项置信度；
 * 同类（category+grade）叠加按 0.7^n 衰减，避免同类重复证据过度拉高分数；
 * 单条强证据把风险下限提升到 25；反 Hook 命中直接判定高风险（>=85）；
 * 白名单命中的证据自动豁免，不计入打分。
 */
#include "rasp_core.h"
#include "rasp_memory.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <unistd.h>

#define CAT_MAX 11

static const char *const kCategories[CAT_MAX] = {
    "mount", "ksu",     "kernel",  "bpf",   "zygisk", "inject",
    "selinux", "antihook", "sandbox", "fops", "other",
};

static int cat_index(const char *cat)
{
    for (int i = 0; i < CAT_MAX; i++) {
        if (strcmp(kCategories[i], cat) == 0) return i;
    }
    return CAT_MAX - 1;
}

static double grade_weight(rasp_grade_t g)
{
    switch (g) {
    case GRADE_STRONG: return 30.0;
    case GRADE_INDIRECT: return 10.0;
    default: return 3.0;
    }
}

/* 自定义权重："MNT-001=40;KSU-001=25" —— 命中则覆盖默认等级权重 */
static double weight_override(const rasp_ctx_t *c, const char *id, double def)
{
    if (c->weight_spec[0] == '\0') return def;
    const char *p = c->weight_spec;
    size_t idlen = strlen(id);
    while (*p) {
        const char *end = strchr(p, ';');
        if (end == NULL) end = p + strlen(p);
        if ((size_t)(end - p) > idlen + 1 && strncmp(p, id, idlen) == 0 && p[idlen] == '=') {
            double v = strtod(p + idlen + 1, NULL);
            if (v > 0.0 && v <= 100.0) return v;
        }
        p = *end ? end + 1 : end;
    }
    return def;
}

static const char *grade_name(rasp_grade_t g)
{
    switch (g) {
    case GRADE_STRONG: return "strong";
    case GRADE_INDIRECT: return "indirect";
    default: return "weak";
    }
}

/*
 * 白名单豁免：按「片段是否足够具体」分级，避免把正常证据整体豁免。
 *  1) 片段与检测项 ID 完全相等 => 显式豁免（任何等级）；
 *  2) 片段长度 < 10 或以 '/' 开头 => 忽略（init、overlay、/data、/system 之类过于泛化）；
 *  3) 强证据只有在片段非常具体（>= 14 字节，且含 '=' / " on " / '.'）时才允许豁免，
 *     避免 "system_server" 这类出现在证据正文里的普通名字把强证据整条豁免；
 *  4) 进程名类通用片段（system_server / zygote64 等）永不参与片段豁免。
 * 剩余情况：对证据 raw 做子串匹配。
 */
static int token_is_generic(const char *t, size_t n)
{
    static const char *const kGeneric[] = {"system_server", "zygote64", "zygote", "init",
                                           "surfaceflinger", "servicemanager"};
    for (size_t i = 0; i < sizeof(kGeneric) / sizeof(kGeneric[0]); i++) {
        if (n == strlen(kGeneric[i]) && strncmp(t, kGeneric[i], n) == 0) return 1;
    }
    return 0;
}

static int contains_sub(const char *hay, size_t haylen, const char *needle, size_t nlen)
{
    if (nlen == 0 || haylen < nlen) return 0;
    for (size_t i = 0; i + nlen <= haylen; i++) {
        if (strncmp(hay + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

static int token_is_specific(const char *t, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (t[i] == '=' || t[i] == '.') return 1;
    }
    return contains_sub(t, n, " on ", 4);
}

static int evidence_whitelisted(rasp_ctx_t *c, const rasp_evidence_t *e)
{
    if (!c->whitelist_enabled) return 0;
    const char *pools[5] = {c->wl_mount, c->wl_proc, c->wl_prop, c->wl_kernel, c->wl_oem};
    size_t idlen = strlen(e->id);
    for (int i = 0; i < 5; i++) {
        if (pools[i][0] == '\0') continue;
        const char *p = pools[i];
        while (*p) {
            const char *sp = strchr(p, ';');
            size_t n = sp ? (size_t)(sp - p) : strlen(p);
            if (n == idlen && strncmp(p, e->id, n) == 0) return 1;
            if (n >= 10 && p[0] != '/' && !token_is_generic(p, n)) {
                int specific = token_is_specific(p, n);
                if (e->grade != GRADE_STRONG || (n >= 14 && specific)) {
                    size_t rawlen = strlen(e->raw);
                    for (size_t off = 0; off + n <= rawlen; off++) {
                        if (strncmp(e->raw + off, p, n) == 0) return 1;
                    }
                }
            }
            if (!sp) break;
            p = sp + 1;
        }
    }
    return 0;
}

int rasp_score_compute(rasp_ctx_t *c, double *out_confidence, const char **out_level)
{
    double score = 0.0;
    double wsum = 0.0, csum = 0.0;
    int strong_hits = 0, indirect_hits = 0, weak_hits = 0, exempted = 0, available = 0;
    int dup[CAT_MAX][3];
    memset(dup, 0, sizeof(dup));

    for (int i = 0; i < c->item_count; i++) {
        rasp_evidence_t *e = &c->items[i];
        if (e->available) available++;
        if (!e->hit) continue;

        if (evidence_whitelisted(c, e)) {
            exempted++;
            continue;
        }

        int ci = cat_index(e->category);
        int gi = (int)e->grade;
        double w = weight_override(c, e->id, grade_weight(e->grade)) * e->confidence;
        double factor = pow(0.7, (double)dup[ci][gi]);
        if (dup[ci][gi] < 3) dup[ci][gi]++;
        score += w * factor;
        wsum += w;
        csum += w * e->confidence;

        if (e->grade == GRADE_STRONG) strong_hits++;
        else if (e->grade == GRADE_INDIRECT) indirect_hits++;
        else weak_hits++;
    }

    int total_hits = strong_hits + indirect_hits + weak_hits;
    (void)exempted;

    /* 单条强证据：风险下限 25（可疑） */
    if (strong_hits > 0 && score < 25.0) score = 25.0;
    /* 反 Hook 特征：直接高风险 */
    if (c->anti_hook_hit && score < 85.0) score = 85.0;
    /* 单一弱线索不参与最终判定（要求 ⑥-3） */
    if (total_hits == 1 && weak_hits == 1) score *= 0.5;

    if (score > 100.0) score = 100.0;
    if (score < 0.0) score = 0.0;

    const char *level = "safe";
    if (score > 50.0) level = "high";
    else if (score > 20.0) level = "suspicious";

    double confidence;
    if (total_hits > 0 && wsum > 0.0) {
        confidence = csum / wsum;
        if (confidence > 0.98) confidence = 0.98;
        if (confidence < 0.05) confidence = 0.05;
    } else {
        confidence = c->item_count > 0 ? (double)available / (double)c->item_count * 0.9 : 0.1;
    }

    if (out_confidence) *out_confidence = confidence;
    if (out_level) *out_level = level;
    return (int)(score + 0.5);
}

void rasp_build_report_json(rasp_ctx_t *c, char *out, size_t cap)
{
    double conf = 0.0;
    const char *level = "safe";
    int score = rasp_score_compute(c, &conf, &level);

    int strong = 0, indirect = 0, weak = 0, hits = 0, available = 0;
    for (int i = 0; i < c->item_count; i++) {
        if (c->items[i].available) available++;
        if (!c->items[i].hit) continue;
        hits++;
        if (c->items[i].grade == GRADE_STRONG) strong++;
        else if (c->items[i].grade == GRADE_INDIRECT) indirect++;
        else weak++;
    }

    char sdk[PROP_VALUE_MAX] = {0}, model[PROP_VALUE_MAX] = {0}, abi[PROP_VALUE_MAX] = {0};
    char rel[PROP_VALUE_MAX] = {0}, tags[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    __system_property_get("ro.product.model", model);
    __system_property_get("ro.product.cpu.abi", abi);
    __system_property_get("ro.build.version.release", rel);
    __system_property_get("ro.build.tags", tags);

    long long now = rasp_now_ms();

    rasp_buf_t b;
    rb_init(&b, out, cap);
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "schema", 1);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "score", score);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "level", level);
    rb_puts(&b, ",");
    rb_json_kv_double(&b, "confidence", conf);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "durationMs", now - c->start_ms);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "startedAt", c->start_ms);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "finishedAt", now);
    rb_puts(&b, ",");

    rb_puts(&b, "\"counts\":{");
    rb_json_kv_int(&b, "strong", strong);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "indirect", indirect);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "weak", weak);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "hits", hits);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "available", available);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "total", c->item_count);
    rb_puts(&b, "},");

    rb_puts(&b, "\"device\":{");
    rb_json_kv_str(&b, "sdk", sdk);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "release", rel);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "model", model);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "abi", abi);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "buildTags", tags);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "pid", (long long)c->self_pid);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "uid", (long long)c->self_uid);
    rb_puts(&b, "},");

    rb_puts(&b, "\"config\":{");
    rb_json_kv_bool(&b, "fastMode", c->fast_mode);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "sandbox", c->sandbox_enabled);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "whitelist", c->whitelist_enabled);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "kernelProbe", c->probe_ready);
    rb_puts(&b, "},");

    rb_puts(&b, "\"antiHook\":{");
    rb_json_kv_bool(&b, "hit", c->anti_hook_hit);
    rb_puts(&b, "},");

    rb_puts(&b, "\"items\":[");
    for (int i = 0; i < c->item_count; i++) {
        rasp_evidence_t *e = &c->items[i];
        if (i > 0) rb_puts(&b, ",");
        rb_puts(&b, "{");
        rb_json_kv_str(&b, "id", e->id);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "name", e->name);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "category", e->category);
        rb_puts(&b, ",");
        rb_json_kv_str(&b, "grade", grade_name(e->grade));
        rb_puts(&b, ",");
        rb_json_kv_double(&b, "confidence", e->confidence);
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
    }
    rb_puts(&b, "]}");
}
