/*
 * =====================================================================================
 *
 *       Filename:  debug_memory.c
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  西元2020年06月26日 22時23分21秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Lai Liang-Wei (github/william6849), william68497@gmail.com
 *   Organization:
 *
 * =====================================================================================
 */

//#include <inttype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define internal_debug_memory
#include "debug_memory.h"

struct fooalign {
    uint8_t a;
    uint64_t b;
};

#define DEFAULT_ALIGNMENT offsetof(struct fooalign, b)
#define MULTIPLE_OF(x)                                             \
    (((x) % DEFAULT_ALIGNMENT)                                     \
         ? (((x) - ((x) % DEFAULT_ALIGNMENT)) + DEFAULT_ALIGNMENT) \
         : (x))

typedef struct header header;
typedef header *headerp;
struct header {
    uint32_t header_magic;
    struct list_head list;
    size_t size;
};
/* start bytes */
#define START_BYTES (MULTIPLE_OF(sizeof(header)))
#define END_BYTES (MULTIPLE_OF(sizeof(uint32_t)))
#define TOTAL_BYTES(x) (START_BYTES + MULTIPLE_OF(x) + END_BYTES)
#define END_OFFSET(x) (START_BYTES + MULTIPLE_OF(x))
#define USAGE_BYTES(x) ((x) - (START_BYTES + END_BYTES))

/* magic numbers */
#define MAGIC_MALLOC 0x12121212
#define MAGIC_FREE 0x23232323
#define MALLOC_FLAG 1
#define FREE_FLAG 0

/* calc */
#define ret_addr(ptr) ((void *) ((char *) ptr + START_BYTES))
#define header_magic(ptr) \
    (((headerp)((char *) ptr - START_BYTES))->header_magic)
#define header_size(ptr) (((headerp)((char *) ptr - START_BYTES))->size)
#define tail_magic(ptr) \
    (*(uint32_t *) ((char *) ptr + MULTIPLE_OF(header_size(ptr))))

/* Default sizes */
#define DEFAULT_BLOCK_SIZE 4096
#define DEBUG_BOUND 65535

struct head_info {
    uint64_t current_heap_size;
    uint32_t free_blocks;
    uint32_t used_blocks;
    uint32_t largest_free_block;
    uint64_t total_free_mem;
};
struct head_info status = {0, 0, 0, 0, 0};

#define get_head(ptr) container_of(ptr, header, list)
#define prev_head(ptr) get_head(ptr->list.prev)
#define next_head(ptr) get_head(ptr->list.next)
/* Free list */
static header freelist;
static headerp lfree = NULL;

/* Functions */
static void set_mem(uint8_t *ptr, size_t size, uint16_t flag);
static headerp get_mem(uint32_t size);
static uint32_t check_magic(headerp ptr, uint16_t flag);
static uint32_t check_free_list(uint32_t *largest);
static uint32_t check_heap(void);

static void set_mem(uint8_t *ptr, size_t size, uint16_t flag)
{
    headerp hmp;
    uint32_t *emp;
    hmp = (headerp) ptr;
    hmp->header_magic = flag ? MAGIC_MALLOC : MAGIC_FREE;
    hmp->size = size;
    emp = (uint32_t *) ((uint8_t *) ptr + END_OFFSET(size));
    *emp = flag ? MAGIC_MALLOC : MAGIC_FREE;
}

static headerp get_mem(uint32_t size)
{
    uint32_t bsize, tsize;
    uint8_t *ptr = NULL;

    tsize = TOTAL_BYTES(size);
    for (bsize = DEFAULT_BLOCK_SIZE;; bsize >>= 1) {
        if (tsize > bsize)
            bsize = tsize;
        else
            bsize = TOTAL_BYTES(bsize);
        if ((ptr = (uint8_t *) malloc(bsize)) != NULL)
            break;
        else if (bsize == tsize)
            return NULL;
    }
    status.current_heap_size += bsize;
    status.used_blocks++;

    set_mem(ptr, USAGE_BYTES(bsize), MAGIC_MALLOC);
    dbg_free(ret_addr(ptr));
    return lfree;
}

static uint32_t check_magic(headerp ptr, uint16_t flag)
{
    uint16_t head, tail;
    head = flag ? (ptr->header_magic == MAGIC_MALLOC)
                : (ptr->header_magic == MAGIC_FREE);
    tail = flag ? (tail_magic(ret_addr(ptr)) == MAGIC_MALLOC)
                : (tail_magic(ret_addr(ptr)) == MAGIC_FREE);
    return (head && tail);
}

static uint32_t check_free_list(uint32_t *largest)
{
    headerp trav;
    uint32_t local_largest = 0;
    uint32_t cnt = 0;
    list_for_each_entry(trav, &(freelist.list), list)
    {
        if (!check_magic(trav, FREE_FLAG)) {
            printf("check_free_list: bad magic number.\n");
            exit(0);
        }
        if (local_largest < trav->size)
            local_largest = trav->size;
        cnt++;
    }
    *largest = local_largest;
    return cnt;
}

void print_free_list(void)
{
    headerp trav;
    uint32_t local_largest = 0;
    uint32_t cnt = 0;
    printf("Free list:\n");
    list_for_each_entry(trav, &(freelist.list), list)
    {
        if (!check_magic(trav, FREE_FLAG)) {
            printf("check_free_list: BAD MAGIC NUMBER.\n");
            exit(0);
        }
        printf("block[%d]->size: %d, ", cnt, trav->size);
        if (local_largest < trav->size)
            local_largest = trav->size;
        cnt++;
        if (!(cnt % 3))
            printf("\n");
    }
    printf("\n");
}

void memory_map(void)
{
    headerp trav;
    headerp inbetween;
    uint32_t cnt = 0;
    uint32_t blk_cnt = status.used_blocks;

    printf("\n");
    list_for_each_entry(trav, &(freelist.list), list)
    {
        cnt++;
        printf("[%d]%p: FREE(%d) ", cnt, ret_addr(trav), trav->size);
        if (!(cnt % 3))
            printf("\n");
        else
            fflush(stdout);

        inbetween = (headerp)((uint8_t *) trav + TOTAL_BYTES(trav->size));
        if (inbetween != next_head(trav)) {
            if (next_head(trav) != &freelist) {
                while (inbetween < next_head(trav)) {
                    /* hit non-malloced block */
                    if (inbetween->header_magic != MAGIC_MALLOC)
                        break;
                    else {
                        if (tail_magic(ret_addr(inbetween)) != MAGIC_MALLOC) {
                            printf("memory_map: CORRUPTED HEAP\n");
                            exit(0);
                        }
                    }
                    cnt++;
                    printf("[%d]%p: MALLOC(%d) ", cnt, ret_addr(inbetween),
                           inbetween->size);
                    if (!(cnt % 3))
                        printf("\n");
                    else
                        fflush(stdout);

                    inbetween = (headerp)((uint8_t *) inbetween +
                                          TOTAL_BYTES(inbetween->size));
                    blk_cnt--;
                }
            } else {
                /* find out left MALLOCED blocks */
                while (blk_cnt) {
                    if (inbetween->header_magic != MAGIC_MALLOC)
                        break;
                    else {
                        if (tail_magic(ret_addr(inbetween)) != MAGIC_MALLOC) {
                            printf("memory_map: CORRUPTED HEAP\n");
                            exit(0);
                        }
                    }
                    cnt++;
                    printf("[%d]%p: MALLOC(%d) ", cnt, ret_addr(inbetween),
                           inbetween->size);
                    if (!(cnt % 3))
                        printf("\n");
                    else
                        fflush(stdout);

                    inbetween = (headerp)((uint8_t *) inbetween +
                                          TOTAL_BYTES(inbetween->size));
                    blk_cnt--;
                }
            }
        }
        printf("\n");
    }
}

uint32_t check_heap(void)
{
    headerp trav, inbetween;
    uint32_t block_cnt = status.used_blocks;
    uint32_t cnt = 0;
    list_for_each_entry(trav, &(freelist.list), list)
    {
        if (!check_magic(trav, FREE_FLAG))
            return 0;
        inbetween = (headerp)((uint8_t *) (trav) + TOTAL_BYTES(trav->size));
        if (inbetween != next_head(trav)) {
            if (next_head(trav) != &freelist) {
                while (inbetween < next_head(trav)) {
                    if (inbetween->header_magic != MAGIC_MALLOC)
                        break;
                    else {
                        if (tail_magic(ret_addr(inbetween)) != MAGIC_MALLOC)
                            return 0;
                    }
                    inbetween = (headerp)((uint8_t *) inbetween +
                                          TOTAL_BYTES(inbetween->size));
                    block_cnt--;
                }
            } else {
                while (block_cnt) {
                    if (inbetween->header_magic != MAGIC_MALLOC)
                        break;
                    else {
                        if (tail_magic(ret_addr(inbetween)) != MAGIC_MALLOC)
                            return 0;
                    }
                    inbetween = (headerp)((uint8_t *) inbetween +
                                          TOTAL_BYTES(inbetween->size));
                    block_cnt--;
                }
            }
        }
    }
    return 1;
}

void *dbg_malloc(uint32_t num_bytes)
{
    headerp trav = NULL, prev;
    if (!num_bytes) {
        printf("dbg_malloc: NULL request.");
        exit(0);
    }
    if (num_bytes > DEBUG_BOUND) {
        printf("dbg_malloc: request:%ld bytes, Upper bound is %ld\n", num_bytes,
               DEBUG_BOUND);
        exit(0);
    }
    if ((prev = lfree) == NULL) {
        INIT_LIST_HEAD(&(freelist.list));
        prev = lfree = &freelist;
        freelist.size = 0;
    }
    for (trav = next_head(prev);; prev = trav, trav = next_head(trav)) {
        if (trav != &freelist) {
            if (!check_magic(trav, FREE_FLAG)) {
                printf("dbg_malloc: BAD MAGIC NUMBER\n");
                exit(0);
            }
        }
        if ((trav->size == MULTIPLE_OF(num_bytes)) ||
            (trav->size >= TOTAL_BYTES(num_bytes))) {
            prev = prev_head(trav);
            if (trav->size == MULTIPLE_OF(num_bytes)) {
                list_del(&(trav->list));
                set_mem((uint8_t *) trav, trav->size, MALLOC_FLAG);
            } else {
                trav->size -= TOTAL_BYTES(num_bytes);
                set_mem((uint8_t *) trav, trav->size, FREE_FLAG);
                trav = (headerp)((uint8_t *) trav + TOTAL_BYTES(trav->size));
                set_mem((uint8_t *) trav, MULTIPLE_OF(num_bytes), MALLOC_FLAG);
            }
            lfree = prev;
            status.used_blocks++;
            return ret_addr(trav);
        }
        if (trav == lfree && ((trav = get_mem(num_bytes)) == NULL))
            return NULL;
    }
}

void dbg_free(void *ptr)
{
    headerp block_header = NULL, trav;
    /* check ptr */
    if (!ptr) {
        printf("dbg_free: Attemp to  free a NULL pointer.\n");
        return;
    } else {
        if (header_magic(ptr) != MAGIC_MALLOC) {
            if (header_magic(ptr) == MAGIC_FREE) {
                printf("dbg_free: Trying to free a freed pointer.\n");
                return;
            } else {
                printf("dbg_free: Trying to free a non-malloced pointer.\n");
                return;
            }
        }

        /* update status */
        status.used_blocks--;
        block_header = (headerp)((uint8_t *) ptr - START_BYTES);
        for (trav = lfree;
             !(trav < block_header && next_head(trav) > block_header);
             trav = next_head(trav)) {
            if (next_head(trav) <= trav &&
                (block_header > trav || block_header < next_head(trav)))
                break;
        }
        if (((uint8_t *) block_header +
             TOTAL_BYTES(block_header->size)) ==  //貼著右邊
            (uint8_t *) next_head(trav)) {
            block_header->size += TOTAL_BYTES(next_head(trav)->size);
            list_del(&(next_head((trav))->list));
            set_mem((uint8_t *) block_header, block_header->size, FREE_FLAG);
        } else {
            set_mem((uint8_t *) block_header, block_header->size, FREE_FLAG);
        }
        __list_add(&(block_header->list), &(trav->list),
                   &(next_head(trav)->list));

        if (((uint8_t *) trav + TOTAL_BYTES(trav->size)) ==  //貼著左邊
            (uint8_t *) block_header) {
            trav->size += TOTAL_BYTES(block_header->size);
            list_del(&(block_header->list));
            set_mem((uint8_t *) trav, trav->size, FREE_FLAG);
        } else {
        }
    }
    lfree = trav;
}


int main()
{
    for (int32_t i = 1; i < 10; i++) {
        uint8_t *str1 = (uint8_t *) dbg_malloc(sizeof(uint8_t) * i * 10);
        print_stats();
        memory_map();
        printf("^^^str1 malloc i*10^^^\n\n");

        dbg_free(str1);
        print_stats();
        memory_map();
        printf("^^^str1 free^^^\n\n");


        char *str2 = (char *) dbg_malloc(sizeof(char) * i * 20);
        print_stats();
        memory_map();
        printf("^^^str2 malloc i*20^^^\n\n");

        char *str3 = (char *) dbg_malloc(sizeof(uint8_t) * i * 30);
        print_stats();
        memory_map();
        printf("^^^str3 malloc i*30^^^\n\n");

        dbg_free(str2);
        print_stats();
        memory_map();
        printf("^^^str2 free^^^\n\n");

        dbg_free(str3);
        print_stats();
        memory_map();
        printf("^^^str3 free^^^\n\n");

        char *str4 = (char *) dbg_malloc(sizeof(char) * i * 40);
        print_stats();
        memory_map();
        printf("^^^str4 malloc i*40^^^\n\n");

        for (int i = 21315; i > 0; i--) {
            str4 = (char *) dbg_realloc(str4, sizeof(char) * i);
        }
        print_stats();
        memory_map();
        printf("$$$str4 realloc \n\n");

        dbg_free(str4);
        print_stats();
        memory_map();
        printf("^^^str4 free^^^\n\n");
    }
    return 0;
}
static void my_strcpy(uint8_t *strDest, uint8_t *strSrc)
{
    uint8_t *tmp = strDest;
    while ((*strDest++ = *strSrc++) != '\0')
        ;
    *strDest = '\0';
}
void *dbg_realloc(void *ptr, size_t size)
{
    if (!ptr) {
        return dbg_malloc(size);
    }
    headerp src = (headerp)((char *) ptr - START_BYTES);
    if (src->size < MULTIPLE_OF(size)) {
        void *tmp = dbg_malloc(size);
        if (!tmp) {
            fprintf(stderr, "dbg_reallc: malloc faild\n");
            return NULL;
        }
        memcpy(tmp, ptr, src->size);
        dbg_free(ptr);
        return tmp;
    } else if (MULTIPLE_OF(src->size) <= TOTAL_BYTES(size)) {
    } else {
        headerp cut = (headerp)((uint8_t *) src + TOTAL_BYTES(size));
        set_mem((uint8_t *) cut, MULTIPLE_OF(src->size) - TOTAL_BYTES(size),
                MALLOC_FLAG);
        dbg_free(ret_addr(cut));
        status.used_blocks++;
        set_mem((uint8_t *) src, MULTIPLE_OF(size), MALLOC_FLAG);
    }
    return ptr;
}
uint8_t *dbg_strdup(uint8_t *instr)
{
    uint8_t *outstr = NULL;

    if (!instr) {
        fprintf(stderr, "strdup: NUILL argument\n");
        return NULL;
    }

    outstr = (uint8_t *) dbg_malloc(sizeof(uint8_t) * (strlen(instr) + 1));
    if (!outstr) {
        fprintf(stderr, "strdup: malloc failed\n");
        return NULL;
    }
    my_strcpy(outstr, instr);
    return outstr;
}
void print_stats()
{
    status.free_blocks = check_free_list(&(status.largest_free_block));
    // status.total_free_mem = (uint64_t)FreeMen();
    printf("Heap Statistics\n");
    printf(" - current heap size: %ld\n", status.current_heap_size);
    printf(" - free blocks : %d\n", status.free_blocks);
    printf(" - used blocks : %d\n", status.used_blocks);
    printf(" - largest free block: %d\n", status.largest_free_block);
    // printf(" - system memory left : %ld\n", status.total_free_mem);
}
