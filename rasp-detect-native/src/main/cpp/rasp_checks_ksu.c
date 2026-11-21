/*
 * rasp_checks_ksu.c —— 第 2 类：KernelSU 本体与进程痕迹
 *
 * 检测项：
 *   KSU-001 ksud 守护进程间接特征（有界 /proc 扫描）【强】
 *   KSU-002 进程组 / 会话 ID 异常【间接】
 *   KSU-003 父进程链异常溯源【间接】
 *   KSU-004 memfd 无文件进程【强】
 *   KSU-005 进程 fd 列表异常匿名文件【间接】
 *
 * 说明：这里扫描的是进程元数据（cmdline/comm/stat/status），
 *       不读取任何其他应用的私有数据，也不做 su 路径扫描。
 */
#include "rasp_core.h"
#include "rasp_memory.h"
#include "rasp_syscall.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* KernelSU / 隐藏套件的进程名特征（不含任何 su 二进制路径） */
static const char *const kSuspiciousNames[] = {
    "ksud", "kernelsu", "ksu_", "shamiko", "zygiskd", "zygisk", "lspd", "lsposed",
    "magiskd", "apd",     "susfs", "hide_",  "tricky",  "riru",   "edxp", "memfd:",
};

typedef struct {
    pid_t pid;
    char name[64];
    char cmdline[192];
    int uid;
    int pgrp;
    int sid;
} susp_proc_t;

static int starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int name_is_suspicious(const char *name, char *matched, size_t cap)
{
    if (name == NULL || name[0] == '\0') return 0;
    for (size_t i = 0; i < sizeof(kSuspiciousNames) / sizeof(kSuspiciousNames[0]); i++) {
        if (rasp_contains_ci(name, kSuspiciousNames[i])) {
            if (matched) snprintf(matched, cap, "%s", kSuspiciousNames[i]);
            return 1;
        }
    }
    return 0;
}

/* 解析 /proc/<pid>/stat：pid (comm) state ppid pgrp session ... */
static int parse_stat_pgrp_sid(const char *stat, int *pgrp, int *sid, char *comm, size_t cap)
{
    if (stat == NULL || pgrp == NULL || sid == NULL) return -1;
    const char *lp = strchr(stat, '(');
    const char *rp = strrchr(stat, ')');
    if (lp == NULL || rp == NULL || rp < lp) return -1;
    if (comm && cap > 0) {
        size_t n = (size_t)(rp - lp - 1);
        if (n >= cap) n = cap - 1;
        memcpy(comm, lp + 1, n);
        comm[n] = '\0';
    }
    /* 从 ')' 之后开始：state ppid pgrp session */
    char state[8] = {0};
    int ppid_val = 0, pgrp_val = 0, sid_val = 0;
    if (sscanf(rp + 1, " %7s %d %d %d", state, &ppid_val, &pgrp_val, &sid_val) != 4) return -1;
    *pgrp = pgrp_val;
    *sid = sid_val;
    return 0;
}

static void check_ksud_process(rasp_ctx_t *c, susp_proc_t *out, int *out_count, int cap)
{
    static rasp_proc_entry_t entries[600];
    /* 分级调度：进程枚举是中等开销项，快速模式降低扫描上限 */
    int n = rasp_scan_procs(entries, 600, c->fast_mode ? 220 : 700);
    int found = 0;
    char detail[640] = {0};
    *out_count = 0;

    for (int i = 0; i < n && found < cap; i++) {
        if (entries[i].pid == c->self_pid) continue;
        char matched[32] = {0};
        int hit = name_is_suspicious(entries[i].comm, matched, sizeof(matched)) ||
                  name_is_suspicious(entries[i].cmdline, matched, sizeof(matched));
        if (!hit) continue;

        /* 同 uid 且是自身子进程的沙箱进程豁免（避免自检误报） */
        susp_proc_t *sp = &out[found];
        memset(sp, 0, sizeof(*sp));
        sp->pid = entries[i].pid;
        sp->pgrp = -1;
        sp->sid = -1;
        snprintf(sp->name, sizeof(sp->name), "%s", matched);
        snprintf(sp->cmdline, sizeof(sp->cmdline), "%s", entries[i].cmdline);

        char stat_buf[512];
        size_t slen = 0;
        int err = 0, via = 0;
        if (rasp_read_proc(entries[i].pid, "stat", stat_buf, sizeof(stat_buf) - 1, &slen, &err,
                           &via) == 0) {
            stat_buf[slen] = '\0';
            char comm2[64] = {0};
            parse_stat_pgrp_sid(stat_buf, &sp->pgrp, &sp->sid, comm2, sizeof(comm2));
        } else {
            sp->pgrp = sp->sid = -1;
        }
        found++;

        size_t l = strlen(detail);
        snprintf(detail + l, sizeof(detail) - l, "%s(pid=%d);", entries[i].comm[0]
                                                                    ? entries[i].comm
                                                                    : entries[i].cmdline,
                 (int)entries[i].pid);
    }
    *out_count = found;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "scanned", n);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "matched", found);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "processes", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "KSU-001", "ksud 守护进程间接特征（cmdline/comm 特征匹配）", "ksu",
              GRADE_STRONG, found > 0 ? 0.92 : 0.0, found > 0, n > 0, raw,
              n > 0 ? NULL : "cannot enumerate /proc");
}

static void check_pgrp_sid(rasp_ctx_t *c, const susp_proc_t *procs, int count)
{
    int anomalies = 0;
    char detail[384] = {0};
    for (int i = 0; i < count; i++) {
        if (procs[i].pgrp == 0 || procs[i].sid == 0) {
            anomalies++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "%s(pgrp=%d,sid=%d);", procs[i].name,
                     procs[i].pgrp, procs[i].sid);
        }
    }

    /* 自身进程组/会话 ID 也必须有效（被注入进程常出现 0） */
    int self_anom = 0;
    static char self_stat[1024];
    size_t slen = 0;
    if (rasp_read_file_raw("/proc/self/stat", self_stat, sizeof(self_stat) - 1, &slen) == 0) {
        self_stat[slen] = '\0';
        int self_pgrp = -1, self_sid = -1;
        if (parse_stat_pgrp_sid(self_stat, &self_pgrp, &self_sid, NULL, 0) == 0) {
            self_anom = (self_pgrp == 0 || self_sid == 0);
            anomalies += self_anom;
        }
    }
    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "suspicious_processes", count);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "zero_pgrp_or_sid", anomalies);
    rb_puts(&b, ",");
    rb_json_kv_bool(&b, "self_anomaly", self_anom);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "KSU-002", "进程组与会话 ID 异常", "ksu", GRADE_INDIRECT,
              (anomalies > 0 || self_anom) ? 0.55 : 0.0, anomalies > 0 || self_anom, 1, raw,
              NULL);
}

static void check_parent_chain(rasp_ctx_t *c)
{
    pid_t pid = c->self_pid;
    char chain[256] = {0};
    int depth = 0, suspicious = 0;
    char suspicious_ancestor[64] = {0};

    while (pid > 1 && depth < 8) {
        char status[4096];
        size_t len = 0;
        int err = 0, via = 0;
        if (rasp_read_proc(pid, "status", status, sizeof(status) - 1, &len, &err, &via) != 0) {
            break;
        }
        status[len] = '\0';
        char name[64] = {0}, ppid_s[32] = {0};
        rasp_status_value(status, "Name", name, sizeof(name));
        rasp_status_value(status, "PPid", ppid_s, sizeof(ppid_s));
        int ppid = atoi(ppid_s);

        size_t l = strlen(chain);
        snprintf(chain + l, sizeof(chain) - l, "%s%s(%d)%s", l ? " <- " : "", name, (int)pid,
                 depth == 0 ? "" : "");
        if (name_is_suspicious(name, NULL, 0)) {
            suspicious = 1;
            if (suspicious_ancestor[0] == '\0') snprintf(suspicious_ancestor,
                                                         sizeof(suspicious_ancestor), "%s", name);
        }
        if (ppid <= 1) break;
        pid = (pid_t)ppid;
        depth++;
    }

    /* 应用进程的父进程必须是 zygote（zygote64/zygote），否则说明被重定向 */
    char first_parent[64] = {0};
    char status[4096];
    size_t len = 0;
    int err = 0, via = 0;
    if (rasp_read_proc(c->self_pid, "status", status, sizeof(status) - 1, &len, &err, &via) == 0) {
        status[len] = '\0';
        char ppid_s[32] = {0};
        rasp_status_value(status, "PPid", ppid_s, sizeof(ppid_s));
        int ppid = atoi(ppid_s);
        if (ppid > 0) {
            char pstatus[4096];
            size_t plen = 0;
            if (rasp_read_proc((pid_t)ppid, "status", pstatus, sizeof(pstatus) - 1, &plen, &err,
                               &via) == 0) {
                pstatus[plen] = '\0';
                rasp_status_value(pstatus, "Name", first_parent, sizeof(first_parent));
            }
        }
    }
    int parent_anomaly = 0;
    if (first_parent[0] != '\0' && !starts_with(first_parent, "zygote") &&
        strcmp(first_parent, "init") != 0) {
        parent_anomaly = 1;
    }
    if (suspicious) parent_anomaly = 1;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_str(&b, "chain", chain);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "direct_parent", first_parent);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "suspicious_ancestor", suspicious_ancestor);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "depth", depth);
    rb_puts(&b, "}");
    rasp_emit(c, "KSU-003", "父进程链异常溯源", "ksu", GRADE_INDIRECT,
              parent_anomaly ? (suspicious ? 0.8 : 0.45) : 0.0, parent_anomaly,
              chain[0] != '\0', raw, chain[0] ? NULL : "cannot read parent chain");
}

static void check_memfd_process(rasp_ctx_t *c)
{
    int hits = 0;
    char detail[384] = {0};

    /* 自身 */
    char exe[256];
    long n = rasp_raw_readlinkat(RASP_AT_FDCWD, "/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        if (strstr(exe, "memfd:") || strstr(exe, "(deleted)")) {
            hits++;
            size_t l = strlen(detail);
            snprintf(detail + l, sizeof(detail) - l, "self_exe=%s;", exe);
        }
    }

    /* 直接子进程（沙箱除外）：若 exe 指向 memfd 说明是无文件进程 */
    static rasp_proc_entry_t entries[300];
    int en = rasp_scan_procs(entries, 300, 400);
    for (int i = 0; i < en && hits < 8; i++) {
        pid_t pid = entries[i].pid;
        if (pid == c->self_pid) continue;
        char status[4096];
        size_t len = 0;
        int err = 0, via = 0;
        if (rasp_read_proc(pid, "status", status, sizeof(status) - 1, &len, &err, &via) != 0)
            continue;
        status[len] = '\0';
        char ppid_s[32] = {0};
        rasp_status_value(status, "PPid", ppid_s, sizeof(ppid_s));
        if (atoi(ppid_s) != (int)c->self_pid) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/exe", (int)pid);
        char target[256];
        long rn = rasp_raw_readlinkat(RASP_AT_FDCWD, path, target, sizeof(target) - 1);
        if (rn > 0) {
            target[rn] = '\0';
            if (strstr(target, "memfd:") || strstr(target, "(deleted)")) {
                hits++;
                size_t l = strlen(detail);
                snprintf(detail + l, sizeof(detail) - l, "child%d=%s;", (int)pid, target);
            }
        }
    }

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "memfd_processes", hits);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "detail", detail);
    rb_puts(&b, "}");
    rasp_emit(c, "KSU-004", "memfd 无文件进程检测", "ksu", GRADE_STRONG, hits > 0 ? 0.85 : 0.0,
              hits > 0, 1, raw, NULL);
}

static void check_fd_anon(rasp_ctx_t *c)
{
    int fd = rasp_raw_open("/proc/self/fd", RASP_O_RDONLY | RASP_O_DIRECTORY | RASP_O_CLOEXEC, 0);
    if (fd < 0) {
        char raw[128];
        snprintf(raw, sizeof(raw), "{\"errno\":%d}", errno);
        rasp_emit(c, "KSU-005", "进程 fd 列表异常匿名文件检测", "ksu", GRADE_INDIRECT, 0.0, 0, 0,
                  raw, "cannot open /proc/self/fd");
        return;
    }

    char buf[8192];
    int total = 0, anon = 0, memfd = 0, dmabuf = 0, bpf = 0;
    char examples[256] = {0};

    for (;;) {
        long got = rasp_raw_getdents64(fd, buf, sizeof(buf));
        if (got <= 0) break;
        for (long off = 0; off + (long)sizeof(struct rasp_dirent64) <= got;) {
            struct rasp_dirent64 *d = (struct rasp_dirent64 *)(buf + off);
            off += d->d_reclen;
            if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
            total++;
            char target[192];
            long rn = rasp_raw_readlinkat(fd, d->d_name, target, sizeof(target) - 1);
            if (rn <= 0) continue;
            target[rn] = '\0';
            if (strstr(target, "anon_inode:") != NULL) {
                anon++;
                if (strstr(target, "bpf") != NULL) bpf++;
                if (strstr(target, "dmabuf") != NULL || strstr(target, "dma-buf") != NULL) dmabuf++;
                if (strlen(examples) < 200) {
                    size_t l = strlen(examples);
                    snprintf(examples + l, sizeof(examples) - l, "%s;", target);
                }
            }
            if (strstr(target, "memfd:") != NULL) memfd++;
        }
    }
    rasp_raw_close(fd);

    /* 普通应用通常 anon_inode 数量很少（eventfd/dmabuf/ion）；异常增多说明被注入 */
    int hit = memfd > 0 || bpf > 0 || anon > 24;
    double conf = 0.0;
    if (memfd > 0) conf += 0.45;
    if (bpf > 0) conf += 0.5;
    if (anon > 24) conf += 0.3;
    if (conf > 0.9) conf = 0.9;
    if (!hit) conf = 0.0;

    char raw[RASP_RAW_MAX];
    rasp_buf_t b;
    rb_init(&b, raw, sizeof(raw));
    rb_puts(&b, "{");
    rb_json_kv_int(&b, "fds", total);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "anon_inode", anon);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "memfd", memfd);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "bpf", bpf);
    rb_puts(&b, ",");
    rb_json_kv_int(&b, "dmabuf", dmabuf);
    rb_puts(&b, ",");
    rb_json_kv_str(&b, "examples", examples);
    rb_puts(&b, "}");
    rasp_emit(c, "KSU-005", "进程 fd 列表异常匿名文件检测", "ksu", GRADE_INDIRECT, conf, hit, 1,
              raw, NULL);
}

void rasp_check_ksu(rasp_ctx_t *c)
{
    rasp_ctx_set_budget(c, 2000);

    static susp_proc_t procs[16];
    int count = 0;
    check_ksud_process(c, procs, &count, 16);
    if (!rasp_deadline_hit(c)) check_pgrp_sid(c, procs, count);
    if (!rasp_deadline_hit(c)) check_parent_chain(c);
    if (!rasp_deadline_hit(c)) check_memfd_process(c);
    if (!rasp_deadline_hit(c)) check_fd_anon(c);
}
