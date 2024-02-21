/*
 * =====================================================================================
 *
 *       Filename:  debug_memory.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  西元2020年06月17日 21時11分44秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lai Liang-Wei (github/william6849), william68497@gmail.com
 *   Organization:
 *
 * =====================================================================================
 */
#ifndef _DEBUG_MEMORY_H_
#define _DEBUG_MEMORY_H_

#include <inttypes.h>
#include "list.h"
#ifndef internal_debug_memory
#define malloc dbg_malloc
#define free dbg_free
#define realloc dbg_realloc
#define strdup dbg_strdup
#endif
/* interfaces */
void print_free_list(void);
void memory_map(void);

void *dbg_malloc(uint32_t num_bytes);
void dbg_free(void *ptr);
void *dbg_realloc(void *ptr, size_t num_bytes);
uint8_t *dbg_strdup(uint8_t *instr);

void print_stats();
#endif
