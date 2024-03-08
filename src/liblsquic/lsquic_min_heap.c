/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_min_heap.c
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "lsquic_min_heap.h"


static void
heapify_min_heap (struct min_heap *heap, unsigned i)
{
    struct min_heap_elem el;
    unsigned smallest;

    assert(i < heap->mh_nelem);

    if (MHE_LCHILD(i) < heap->mh_nelem)
    {
        if (heap->mh_elems[ MHE_LCHILD(i) ].mhe_val <
                                    heap->mh_elems[ i ].mhe_val)
            smallest = MHE_LCHILD(i);
        else
            smallest = i;
        if (MHE_RCHILD(i) < heap->mh_nelem &&
            heap->mh_elems[ MHE_RCHILD(i) ].mhe_val <
                                    heap->mh_elems[ smallest ].mhe_val)
            smallest = MHE_RCHILD(i);
    }
    else
        smallest = i;

    if (smallest != i)
    {
        el = heap->mh_elems[ smallest ];
        heap->mh_elems[ smallest ] = heap->mh_elems[ i ];
        heap->mh_elems[ i ] = el;
        heapify_min_heap(heap, smallest);
    }
}


/* 将item按照val值排序(小到大)插入堆 */
void
lsquic_mh_insert (struct min_heap *heap, void *item, uint64_t val)
{
    struct min_heap_elem el;
    unsigned i;

    assert(heap->mh_nelem < heap->mh_nalloc);

    /* 先放入堆尾 */
    heap->mh_elems[ heap->mh_nelem ].mhe_item = item;
    heap->mh_elems[ heap->mh_nelem ].mhe_val  = val;
    ++heap->mh_nelem;

    /* 使用堆排序: 从下往上堆化 */
    i = heap->mh_nelem - 1;
    while (i > 0 && heap->mh_elems[ MHE_PARENT(i) ].mhe_val >
                                    heap->mh_elems[ i ].mhe_val)
    {
        el = heap->mh_elems[ MHE_PARENT(i) ];
        heap->mh_elems[ MHE_PARENT(i) ] = heap->mh_elems[ i ];
        heap->mh_elems[ i ] = el;
        i = MHE_PARENT(i);
    }
}


/* 获取首个并删除 */
void *
lsquic_mh_pop (struct min_heap *heap)
{
    void *item;

    if (heap->mh_nelem == 0)
        return NULL;

    item = heap->mh_elems[0].mhe_item; /* 堆顶为最小值 */
    --heap->mh_nelem;
    if (heap->mh_nelem > 0)
    {
	/* 堆排序: 最后结点放到堆顶, 然后从上往下堆化排序 */
        heap->mh_elems[0] = heap->mh_elems[ heap->mh_nelem ];
        heapify_min_heap(heap, 0);
    }

    return item;
}
