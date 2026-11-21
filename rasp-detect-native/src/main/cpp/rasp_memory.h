/* rasp_memory.h —— maps 解析与函数入口校验 */
#ifndef RASP_MEMORY_H
#define RASP_MEMORY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t start;
    uint64_t end;
    char perms[8];
    char path[192];
} rasp_map_t;

typedef struct {
    int total;
    int rwx;
    int anon_exec;
    int memfd_exec;
    int deleted_exec;
    int suspicious_path;
    char suspicious_example[192];
    int art_segments;
    int art_writable;
    int libc_segments;
    int big_anon_rw;
} rasp_maps_stats_t;

int rasp_maps_load(rasp_map_t *out, int cap);
int rasp_maps_find_module(const char *needle, uint64_t *start, uint64_t *end);
int rasp_maps_stats(rasp_maps_stats_t *st);
int rasp_check_function_entry(void *addr, const char *module_hint, char *detail, size_t detail_cap);

#endif /* RASP_MEMORY_H */
