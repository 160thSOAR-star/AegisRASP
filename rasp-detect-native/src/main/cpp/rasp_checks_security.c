/*
 * rasp_checks_security.c —— 第 7 类：SELinux & AVB & 系统完整性间接检测
 *
 * 检测项：
 *   SEL-001 SELinux 域上下文异常【间接】
 *   SEL-002 SELinux 策略偏离度【弱线索】
 *   SEL-003 AVB2.0 校验状态【弱线索】
 *   SEL-004 系统分区完整性间接校验【间接】
 *   SEL-005 系统属性异常特征（属性区 vs 磁盘 build.prop）【间接】
 */
#include "rasp_core.h"
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

/* ------------------------------------------------------------------ SEL-001 */

static void check_selinux_context(rasp_ctx_t *c)
{
    static char ctx[512];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "attr/current", ctx, sizeof(ctx) - 1, &len, &err, &via) != 0) {
        if (rasp_read_file_raw("/proc/self/attr/current", ctx, sizeof(ctx) - 1, &len) != 0) {
            char raw[128];
            snprintf(raw, sizeof(raw), "{\"errno\":%d}", err);
            rasp_emit(c, "SEL-001", "SELinux 域上下文异常检测", "selinux", GRADE_INDIRECT, 0.0, 0,
                      0, raw, "cannot read attr/current");
            return;
        }
    }
    ctx[len] = '\0';
    char *nl = strchr(ctx, '\n');
    if (nl) *nl = '\0';

    int untrusted = strstr(ctx, "untrusted_app") != NULL;
    int privileged = strstr(ctx, "platform_app") != NULL || strstr(ctx, "system_app") != NULL;
    int su_domain = strstr(ctx, ":su:") != NULL || strstr(ctx, "magisk") != NULL ||
                    strstr(ctx, "ksu") != NULL;

    int hit = !untrusted && !privileged;
    double conf = 0.0;
    if (su_domain) conf = 0.95;
    else if (hit) conf = 0.55;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "context", ctx);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "untrusted_app", untrusted);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "escalated_domain", su_domain);
    rb_puts(&b, "}");
    rasp_emit(c, "SEL-001", "SELinux 域上下文异常检测", "selinux", GRADE_INDIRECT, conf, hit, 1,
              raw, NULL);
}

/* ------------------------------------------------------------------ SEL-002 */

static void check_selinux_policy(rasp_ctx_t *c)
{
    char policyvers[32] = {0}, enforce[32] = {0}, checkreqprot[32] = {0};
    size_t len = 0;
    if (rasp_read_file_raw("/sys/fs/selinux/policyvers", policyvers, sizeof(policyvers) - 1,
                           &len) == 0) {
        policyvers[len] = '\0';
    }
    if (rasp_read_file_raw("/sys/fs/selinux/enforce", enforce, sizeof(enforce) - 1, &len) == 0) {
        enforce[len] = '\0';
    }
    if (rasp_read_file_raw("/sys/fs/selinux/checkreqprot", checkreqprot,
                           sizeof(checkreqprot) - 1, &len) == 0) {
        checkreqprot[len] = '\0';
    }
    int pv = atoi(policyvers);
    int enf = atoi(enforce);

    int permissive = (enforce[0] != '\0' && enf == 0);
    int low_policy = (pv > 0 && pv < 30);

    int hit = permissive || low_policy;
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "policyvers", pv);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "enforce", enf);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "checkreqprot", checkreqprot);
    rb_puts(&b, "}");
    rasp_emit(c, "SEL-002", "SELinux 策略偏离度检测", "selinux", GRADE_WEAK,
              hit ? (permissive ? 0.5 : 0.25) : 0.0, hit, policyvers[0] != 0, raw,
              policyvers[0] ? NULL : "selinuxfs not readable");
}

/* ------------------------------------------------------------------ SEL-003 */

static void check_avb(rasp_ctx_t *c)
{
    char vbs[PROP_VALUE_MAX] = {0}, locked[PROP_VALUE_MAX] = {0};
    char device_state[PROP_VALUE_MAX] = {0}, verity[PROP_VALUE_MAX] = {0};
    char warranty[PROP_VALUE_MAX] = {0}, vbmeta_state[PROP_VALUE_MAX] = {0};

    prop_get("ro.boot.verifiedbootstate", vbs, sizeof(vbs));
    prop_get("ro.boot.flash.locked", locked, sizeof(locked));
    prop_get("ro.boot.vbmeta.device_state", device_state, sizeof(device_state));
    prop_get("ro.boot.veritymode", verity, sizeof(verity));
    prop_get("ro.boot.warranty_bit", warranty, sizeof(warranty));
    prop_get("ro.boot.vbmeta.digest", vbmeta_state, sizeof(vbmeta_state));

    int orange = strcmp(vbs, "orange") == 0;
    int red = strcmp(vbs, "red") == 0;
    int unlocked = locked[0] != '\0' && strcmp(locked, "1") != 0;
    int device_unlocked = strcmp(device_state, "unlocked") == 0;

    int hit = orange || red || unlocked || device_unlocked;
    double conf = 0.0;
    if (red) conf = 0.7;
    else if (orange) conf = 0.55;
    else if (unlocked || device_unlocked) conf = 0.4;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "verifiedbootstate", vbs);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "flash_locked", locked);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "vbmeta_device_state", device_state);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "veritymode", verity);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "warranty_bit", warranty);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "vbmeta_digest_present", vbmeta_state[0] != '\0');
    rb_puts(&b, "}");
    rasp_emit(c, "SEL-003", "AVB2.0 校验状态检测", "selinux", GRADE_WEAK, conf, hit,
              vbs[0] != '\0', raw, vbs[0] ? NULL : "avb properties unavailable");
}

/* ------------------------------------------------------------------ SEL-004 */

static void check_system_partition(rasp_ctx_t *c)
{
    static char mi[128 * 1024];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "mountinfo", mi, sizeof(mi) - 1, &len, &err, &via) != 0) {
        rasp_emit(c, "SEL-004", "系统分区完整性间接校验", "selinux", GRADE_INDIRECT, 0.0, 0, 0,
                  NULL, "cannot read mountinfo");
        return;
    }
    mi[len] = '\0';

    int rw_system = 0, overlay_system = 0, tmpfs_system = 0;
    const char *p = mi;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        char line[1024];
        if (llen >= sizeof(line)) llen = sizeof(line) - 1;
        memcpy(line, p, llen);
        line[llen] = '\0';
        int system_mount = (strstr(line, " /system ") != NULL ||
                            strstr(line, " /vendor ") != NULL ||
                            strstr(line, " /product ") != NULL);
        if (system_mount && strstr(line, " rw,") != NULL) rw_system++;
        if (system_mount && strstr(line, " - overlay ") != NULL) overlay_system++;
        if (system_mount && strstr(line, " - tmpfs ") != NULL) tmpfs_system++;
        if (!eol) break;
        p = eol + 1;
    }

    int hit = rw_system > 0 || overlay_system > 0 || tmpfs_system > 0;
    double conf = 0.0;
    if (overlay_system > 0) conf += 0.6;
    if (tmpfs_system > 0) conf += 0.55;
    if (rw_system > 0) conf += 0.45;
    if (conf > 0.9) conf = 0.9;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "rw_system_mounts", rw_system);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "overlay_system_mounts", overlay_system);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "tmpfs_system_mounts", tmpfs_system);
    rb_puts(&b, "}");
    rasp_emit(c, "SEL-004", "系统分区完整性间接校验", "selinux", GRADE_INDIRECT, conf, hit, 1, raw,
              NULL);
}

/* ------------------------------------------------------------------ SEL-005 */

typedef struct {
    const char *prop;
    const char *path;
    const char *disk_key;
} prop_probe_t;

static int parse_build_prop(const char *buf, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t kl = strlen(key);
    const char *p = buf;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t llen = eol ? (size_t)(eol - p) : strlen(p);
        if (llen > kl + 1 && strncmp(p, key, kl) == 0 && p[kl] == '=') {
            size_t n = llen - kl - 1;
            if (n >= cap) n = cap - 1;
            memcpy(out, p + kl + 1, n);
            out[n] = '\0';
            /* 去掉行尾 \r */
            size_t ol = strlen(out);
            while (ol > 0 && (out[ol - 1] == '\r')) out[--ol] = '\0';
            return 0;
        }
        if (!eol) break;
        p = eol + 1;
    }
    return -1;
}

static void check_properties(rasp_ctx_t *c)
{
    static char build_prop[128 * 1024];
    size_t blen = 0;
    int have_disk = rasp_read_file_raw("/system/build.prop", build_prop, sizeof(build_prop) - 1,
                                       &blen) == 0;
    if (have_disk) build_prop[blen] = '\0';

    static const prop_probe_t probes[] = {
        {"ro.build.tags", "/system/build.prop", "ro.build.tags"},
        {"ro.build.version.sdk", "/system/build.prop", "ro.build.version.sdk"},
        {"ro.product.model", "/system/build.prop", "ro.product.model"},
        {"ro.build.fingerprint", "/system/build.prop", "ro.build.fingerprint"},
    };

    int mismatches = 0, checked = 0;
    char detail[512] = {0};
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        char live[PROP_VALUE_MAX] = {0}, disk[PROP_VALUE_MAX] = {0};
        prop_get(probes[i].prop, live, sizeof(live));
        if (!have_disk) break;
        if (parse_build_prop(build_prop, probes[i].disk_key, disk, sizeof(disk)) != 0) continue;
        checked++;
        if (live[0] && disk[0] && strcmp(live, disk) != 0) {
            mismatches++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(prop=%s,disk=%s);", probes[i].prop, live,
                     disk);
        }
    }

    char tags[PROP_VALUE_MAX] = {0}, debuggable[PROP_VALUE_MAX] = {0};
    prop_get("ro.build.tags", tags, sizeof(tags));
    prop_get("ro.debuggable", debuggable, sizeof(debuggable));
    int test_keys = tags[0] && strstr(tags, "test-keys") != NULL;
    int debuggable_1 = debuggable[0] == '1';

    int hit = mismatches > 0;
    double conf = 0.0;
    if (mismatches > 0) conf = 0.75;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "checked", checked);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "mismatches", mismatches);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "test_keys", test_keys);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "debuggable", debuggable_1);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "build_tags", tags);
    rb_puts(&b, "}");
    /* test-keys / debuggable 仅作为弱线索参考，不单独升级风险（避免 userdebug 误报） */
    rasp_emit(c, "SEL-005", "系统属性异常特征（属性区 vs build.prop）", "selinux", GRADE_INDIRECT,
              conf, hit, checked > 0, raw,
              checked > 0 ? NULL : "build.prop not readable (scoped storage/SELinux)");
}

void rasp_check_security(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 1800);
    check_selinux_context(c);
    if (!rasp_deadline_hit(c)) check_selinux_policy(c);
    if (!rasp_deadline_hit(c)) check_avb(c);
    if (!rasp_deadline_hit(c)) check_system_partition(c);
    if (!rasp_deadline_hit(c)) check_properties(c);
}
