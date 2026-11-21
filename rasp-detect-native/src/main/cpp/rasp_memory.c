/*
 * rasp_memory.c —— /proc/self/maps 解析与函数入口完整性检查
 *
 * 说明：函数入口检查只读取本进程内的只读代码字节（用户态可读），
 *       不做任何写入、不做 ptrace，符合“纯检测、非攻击”的边界。
 */
#include "rasp_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rasp_memory.h"

int rasp_maps_load(rasp_map_t *out, int cap)
{
    if (out == NULL || cap <= 0) return -1;
    static char buf[192 * 1024];
    size_t len = 0;
    if (rasp_read_file_raw("/proc/self/maps", buf, sizeof(buf), &len) != 0) return -1;

    int n = 0;
    char *line = buf;
    while (*line && n < cap) {
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        rasp_map_t *m = &out[n];
        memset(m, 0, sizeof(*m));
        unsigned long long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) == 3) {
            m->start = (uint64_t)start;
            m->end = (uint64_t)end;
            snprintf(m->perms, sizeof(m->perms), "%s", perms);
            /* path 位于第 6 个字段之后 */
            char *p = line;
            for (int i = 0; i < 5 && p; i++) {
                p = strchr(p, ' ');
                if (p) p++;
                while (p && *p == ' ') p++;
            }
            if (p && *p) {
                snprintf(m->path, sizeof(m->path), "%s", p);
            } else {
                m->path[0] = '\0';
            }
            n++;
        }
        if (!eol) break;
        line = eol + 1;
    }
    return n;
}

int rasp_maps_find_module(const char *needle, uint64_t *start, uint64_t *end)
{
    static rasp_map_t maps[512];
    int n = rasp_maps_load(maps, 512);
    if (n <= 0) return -1;
    for (int i = 0; i < n; i++) {
        if (maps[i].path[0] && strstr(maps[i].path, needle)) {
            if (start) *start = maps[i].start;
            if (end) *end = maps[i].end;
            return 0;
        }
    }
    return -1;
}

/* 统计匿名可执行映射、rwx 映射、异常来源映射数量 */
int rasp_maps_stats(rasp_maps_stats_t *st)
{
    if (st == NULL) return -1;
    static rasp_map_t maps[1024];
    int n = rasp_maps_load(maps, 1024);
    if (n <= 0) return -1;
    memset(st, 0, sizeof(*st));
    st->total = n;
    for (int i = 0; i < n; i++) {
        const char *p = maps[i].perms;
        int w = p[1] == 'w', x = p[2] == 'x';
        /* ART 的 JIT 代码缓存本身就是 memfd 映射，属正常现象，必须排除 */
        int is_jit = strstr(maps[i].path, "jit") != NULL ||
                     strstr(maps[i].path, "dalvik") != NULL ||
                     strstr(maps[i].path, "boot.art") != NULL ||
                     strstr(maps[i].path, "boot.oat") != NULL;
        if (w && x && !is_jit) st->rwx++;
        if (x && maps[i].path[0] == '\0') st->anon_exec++;
        if (x && strstr(maps[i].path, "memfd:") && !is_jit) st->memfd_exec++;
        if (x && !is_jit && strstr(maps[i].path, "(deleted)")) st->deleted_exec++;
        if (strstr(maps[i].path, "/data/adb/") || strstr(maps[i].path, "zygisk") ||
            strstr(maps[i].path, "riru") || strstr(maps[i].path, "lspd") ||
            strstr(maps[i].path, "edxp")) {
            st->suspicious_path++;
            if (st->suspicious_example[0] == '\0') {
                snprintf(st->suspicious_example, sizeof(st->suspicious_example), "%s",
                         maps[i].path);
            }
        }
        if (strstr(maps[i].path, "libart.so")) {
            st->art_segments++;
            /* 只有「可写且可执行」的 libart 代码段才是 Hook 痕迹 */
            if (w && x) st->art_writable++;
        }
        if (strstr(maps[i].path, "libc.so")) st->libc_segments++;
        if ((uint64_t)(maps[i].end - maps[i].start) > 64ULL * 1024 * 1024 &&
            maps[i].path[0] == '\0' && w) {
            st->big_anon_rw++;
        }
    }
    return 0;
}

/*
 * 函数入口完整性检查（ARM64 / x86_64）
 * 返回：0 = 正常，1 = 可疑（跳板/断点/越界），-1 = 无法判定
 */
int rasp_check_function_entry(void *addr, const char *module_hint, char *detail, size_t detail_cap)
{
    if (addr == NULL) return -1;
    uint64_t start = 0, end = 0;
    if (module_hint && rasp_maps_find_module(module_hint, &start, &end) != 0) {
        snprintf(detail, detail_cap, "module %s not found in maps", module_hint);
        return -1;
    }
    uint64_t a = (uint64_t)(uintptr_t)addr;
    if (start && (a < start || a >= end)) {
        snprintf(detail, detail_cap,
                 "address 0x%llx outside %s [0x%llx-0x%llx]",
                 (unsigned long long)a, module_hint, (unsigned long long)start,
                 (unsigned long long)end);
        return 1;
    }

    const unsigned char *code = (const unsigned char *)addr;
    snprintf(detail, detail_cap, "prologue=");
    size_t off = strlen(detail);

#if defined(__aarch64__)
    /* 读取 2 条指令（8 字节），全部经 /proc/self/mem 之外的直接内存读取 */
    uint32_t insn[2] = {0, 0};
    memcpy(insn, code, sizeof(insn));
    for (int i = 0; i < 2 && off + 12 < detail_cap; i++) {
        off += (size_t)snprintf(detail + off, detail_cap - off, "%08x", insn[i]);
        if (i == 0) off += (size_t)snprintf(detail + off, detail_cap - off, ",");
    }
    if ((insn[0] & 0xFC000000u) == 0x14000000u) {
        /* B：bionic 存在 ifunc/别名的合法跳转桩，只有跳到模块外才是 Hook */
        int32_t imm26 = (int32_t)(insn[0] & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000u; /* 符号扩展 */
        uint64_t target = a + (uint64_t)((int64_t)imm26 * 4);
        if (start && target >= start && target < end) {
            snprintf(detail, detail_cap, "B thunk within module -> 0x%llx",
                     (unsigned long long)target);
            return 0;
        }
        snprintf(detail, detail_cap, "B at entry jumps outside module -> 0x%llx",
                 (unsigned long long)target);
        return 1;
    }
    if ((insn[0] & 0xFC000000u) == 0x94000000u) {
        int32_t imm26 = (int32_t)(insn[0] & 0x03FFFFFFu);
        if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000u;
        uint64_t target = a + (uint64_t)((int64_t)imm26 * 4);
        if (start && target >= start && target < end) {
            snprintf(detail, detail_cap, "BL thunk within module -> 0x%llx",
                     (unsigned long long)target);
            return 0;
        }
        snprintf(detail, detail_cap, "BL at entry jumps outside module -> 0x%llx",
                 (unsigned long long)target);
        return 1;
    }
    if ((insn[0] & 0xFFFFFC1Fu) == 0xD61F0000u) {
        snprintf(detail, detail_cap, "BR at entry (trampoline) insn=%08x", insn[0]);
        return 1;
    }
    if (insn[0] == 0xD503201Fu) {
        snprintf(detail, detail_cap, "NOP at entry (patched placeholder)");
        return 1;
    }
    if ((insn[0] & 0xFFE0001Fu) == 0xD4200000u) {
        snprintf(detail, detail_cap, "BRK at entry (breakpoint/hook) insn=%08x", insn[0]);
        return 1;
    }
    if (insn[0] == 0x00000000u && insn[1] == 0x00000000u) {
        snprintf(detail, detail_cap, "zeroed code (memory patch)");
        return 1;
    }
#elif defined(__x86_64__)
    unsigned char b[8];
    memcpy(b, code, sizeof(b));
    for (int i = 0; i < 8 && off + 4 < detail_cap; i++) {
        off += (size_t)snprintf(detail + off, detail_cap - off, "%02x", b[i]);
    }
    if (b[0] == 0xE9 || b[0] == 0xEB) {
        /* 短跳/近跳：目标落在本模块内是合法桩，跳到模块外才是 Hook */
        int32_t rel = 0;
        uint64_t target;
        if (b[0] == 0xE9) {
            memcpy(&rel, b + 1, sizeof(rel));
            target = a + 5 + (uint64_t)(int64_t)rel;
        } else {
            rel = (int8_t)b[1];
            target = a + 2 + (uint64_t)(int64_t)rel;
        }
        if (start && target >= start && target < end) {
            snprintf(detail, detail_cap, "jmp thunk within module -> 0x%llx",
                     (unsigned long long)target);
            return 0;
        }
        snprintf(detail, detail_cap, "jmp at entry leaves module -> 0x%llx",
                 (unsigned long long)target);
        return 1;
    }
    if (b[0] == 0xCC) {
        snprintf(detail, detail_cap, "int3 at entry");
        return 1;
    }
    /* push %rbp; mov %rsp,%rbp / endbr64 / sub $imm,%rsp / GOT 间接跳转桩都是正常序言 */
    int endbr64 = (b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && b[3] == 0xFA);
    int indirect_jmp = (b[0] == 0xFF && b[1] == 0x25);
    if (!endbr64 && !indirect_jmp && b[0] != 0x55 &&
        !(b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) &&
        !(b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) &&
        !(b[0] == 0x48 && b[1] == 0x89) && b[0] != 0x53 && b[0] != 0x41) {
        snprintf(detail, detail_cap, "unrecognized prologue %02x %02x %02x", b[0], b[1], b[2]);
        return 1;
    }
#endif
    if (detail[0] == '\0') snprintf(detail, detail_cap, "normal");
    return 0;
}
