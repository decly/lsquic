/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_conn_flow.h -- Connection flow control-related functions
 */

#ifndef LSQUIC_CONN_FLOW_H
#define LSQUIC_CONN_FLOW_H 1

struct lsquic_conn_public;

typedef struct lsquic_cfcw { /* 连接级别的流控, 控制所有流之和 */
    struct lsquic_conn_public
                 *cf_conn_pub;
    uint64_t      cf_max_recv_off;  /* Largest offset observed (cumulative) */
                                    /* 记录接收到的最大数据偏移(所有流累加) */
    uint64_t      cf_recv_off;      /* Flow control receive offset */
                                    /* 连接流控的大小偏移
                                     * 所有流的偏移相加(cf_max_recv_off)超过它则认为超出连接流控
                                     */
    uint64_t      cf_read_off;      /* Number of bytes consumed (cumulative) */
    lsquic_time_t cf_last_updated;
    unsigned      cf_max_recv_win;  /* Maximum receive window */
} lsquic_cfcw_t;

struct lsquic_conn_cap {
    uint64_t cc_sent;           /* Number of bytes sent on connection */
    uint64_t cc_max;            /* Maximum cumulative number of bytes allowed
                                 * to be sent on this connection.
                                 */
                                /* 连接级别的最大数据量, 表示流控中可发送的最大数据量
                                 * 从对端发送的最大数据量(QUIC_FRAME_MAX_DATA)帧得到
                                 */
    uint64_t cc_blocked;        /* Last blocked offset used */
};


#define lsquic_conn_cap_init(cc, max) do {                          \
    (cc)->cc_sent = 0;                                              \
    (cc)->cc_max = max;                                             \
} while (0)


#define lsquic_conn_cap_avail(cap) (                                \
    (assert((cap)->cc_max >= (cap)->cc_sent)),                      \
        (cap)->cc_max - (cap)->cc_sent)


void
lsquic_cfcw_init (lsquic_cfcw_t *, struct lsquic_conn_public *,
                                        unsigned initial_max_recv_window);

/* If update is to be sent, updates max_recv_off and returns true.  Note
 * that if you call this function twice, the second call will return false.
 */
int
lsquic_cfcw_fc_offsets_changed (lsquic_cfcw_t *);

#define lsquic_cfcw_get_fc_recv_off(fc) (+(fc)->cf_recv_off)

#define lsquic_cfcw_get_max_recv_off(fc) (+(fc)->cf_max_recv_off)

#define lsquic_cfcw_get_max_recv_window(fc) (+(fc)->cf_max_recv_win)

/* Returns false if flow control violation is encountered */
int
lsquic_cfcw_incr_max_recv_off (lsquic_cfcw_t *, uint64_t);

/* Void because we do not expect the caller to make a mistake.
 */
void
lsquic_cfcw_incr_read_off (lsquic_cfcw_t *, uint64_t);

#endif
