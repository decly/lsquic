/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_rtt.c -- RTT calculation
 */

#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif

#include "lsquic_int_types.h"
#include "lsquic_rtt.h"

/* See RFC 2988 */

#define ALPHA_SHIFT 3   /* Alpha is 1/8 */
#define BETA_SHIFT  2   /* Beta is 1/4 */


void
lsquic_rtt_stats_update (struct lsquic_rtt_stats *stats,
                         lsquic_time_t send_delta, lsquic_time_t lack_delta)
{
    /* rtt不包括对端处理时延 */
    if (send_delta > lack_delta)
        send_delta -= lack_delta;
    if (stats->srtt) {
        /* 计算srtt和rttvar:
         * rttvar = 3/4 rttvar + 1/4 |rtt - srtt|
         * srtt = 7/8 srtt + 1/8 rtt
         */
        stats->rttvar -= stats->rttvar >> BETA_SHIFT;
        // FIXED: subtracting unsigned (the (int) cast gets repromoted to uint64_t
        // made abs() irrelevant and allowed overflow. instead cast the difference
        // to a signed int64 and use labs() to get abs val.
        stats->rttvar += (llabs((int64_t) (send_delta - stats->srtt)))
                                                            >> BETA_SHIFT;
        stats->srtt -= stats->srtt >> ALPHA_SHIFT;
        stats->srtt += send_delta >> ALPHA_SHIFT;
        if (send_delta < stats->min_rtt)
            stats->min_rtt = send_delta;
    } else {
        /* First measurement */
        stats->srtt   = send_delta;
        stats->rttvar = send_delta >> 1;
        stats->min_rtt = send_delta;
    }
}
