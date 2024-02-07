/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rechist.h -- History of received packets.
 *
 * The purpose of received packet history is to generate ACK frames.
 */

#ifndef LSQUIC_RECHIST_H
#define LSQUIC_RECHIST_H 1

#ifndef LSQUIC_TEST
#define LSQUIC_TEST 0
#endif

/* Structure is exposed to facilitate some manipulations in unit tests. */
struct rechist_elem {   /* 代表一个包号区间范围 [re_low, re_low + re_count) */
    lsquic_packno_t     re_low;     /* 最小包号 */
    unsigned            re_count;   /* 从re_low起连续的包号个数 */
    unsigned            re_next;    /* UINT_MAX means no next element */
                                    /* 指向下一个包号区间的rh_elems索引(递减排序) */
};


struct lsquic_rechist { /* 管理接收到的包号区间 */
    /* elems and masks are allocated in contiguous memory */
    struct rechist_elem            *rh_elems;   /* 包号区间数组(链表), 是按照包号递减排序的,
                                                 * 用数组实现链表: rh_head为首个区间索引,
                                                 * 然后每个区间的re_next指向下一个区间的索引,
                                                 * 最后一个的re_next为UINT_MAX
                                                 */
    uintptr_t                      *rh_masks;       /* 位掩码, 用来表示rh_elems中那些项被使用了 */
    lsquic_packno_t                 rh_cutoff;
    lsquic_time_t                   rh_largest_acked_received;  /* 最大包号接收的时间 */
    unsigned                        rh_n_masks;
    unsigned                        rh_n_alloced;   /* rh_elems分配的个数, 初始为4, 用满了扩大一倍分配 */
    unsigned                        rh_n_used;      /* rh_elems使用的个数 */
    unsigned                        rh_head;        /* 首个包号区间(最大包号)在rh_elems的数组索引
                                                     * 所以是从rh_elems[rh_head]开始遍历的
                                                     */
    unsigned                        rh_max_ranges;  /* rh_elems最大可分配个数, 即rh_n_alloced的上限
                                                     * iquic中根据不同包空间不一样:
                                                     * PNS_INIT/PNS_HSK为10, PNS_APP为1000
                                                     */
    enum {
        RH_CUTOFF_SET   = (1 << 0),
    }                               rh_flags;
    struct
    {
        struct lsquic_packno_range      range;
        unsigned                        next;
    }                               rh_iter;
};

typedef struct lsquic_rechist lsquic_rechist_t;

void
lsquic_rechist_init (struct lsquic_rechist *, int is_ietf, unsigned max_ranges);

void
lsquic_rechist_cleanup (struct lsquic_rechist *);

enum received_st {
    REC_ST_OK,  /* 合法的包号 */
    REC_ST_DUP, /* 重复的包号 */
    REC_ST_ERR, /* 非法包号 */
};

enum received_st
lsquic_rechist_received (lsquic_rechist_t *, lsquic_packno_t,
                         lsquic_time_t now);

void
lsquic_rechist_stop_wait (lsquic_rechist_t *, lsquic_packno_t);

const struct lsquic_packno_range *
lsquic_rechist_first (lsquic_rechist_t *);

const struct lsquic_packno_range *
lsquic_rechist_next (lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_largest_packno (const lsquic_rechist_t *);

lsquic_packno_t
lsquic_rechist_cutoff (const lsquic_rechist_t *);

lsquic_time_t
lsquic_rechist_largest_recv (const lsquic_rechist_t *);

size_t
lsquic_rechist_mem_used (const struct lsquic_rechist *);

const struct lsquic_packno_range *
lsquic_rechist_peek (struct lsquic_rechist *);

#define lsquic_rechist_is_empty(rechist_) ((rechist_)->rh_n_used == 0)

int
lsquic_rechist_copy_ranges (struct lsquic_rechist *, void *rechist_ctx,
    const struct lsquic_packno_range * (*first) (void *),
    const struct lsquic_packno_range * (*next) (void *));

#endif
