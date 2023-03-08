/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#ifndef LSQUIC_BBR_H
#define LSQUIC_BBR_H

/* Our BBR implementation is copied from Chromium with some modifications.
 * Besides the obvious translation from C++ to C, differences are:
 *
 *  1. Instead of OnCongestionEvent(), the ACK information is processed at the
 *     same time as the ACK itself using cci_begin_ack(), cci_ack(), and
 *     cci_end_ack() methods.  This is done to fit with the flow in
 *     lsquic_send_ctl_got_ack().
 *
 *  2. The bandwidth sampler does not use a hash.  Instead, the sample
 *     information is attached directly to the packet via po_bwp_state.
 *
 * In this file and in lsquic_bbr.c, C++-style comments are those copied
 * verbatim from Chromium.  C-style comments are ours.
 *
 * Code is based on bbr_sender.cc 1a578a76c16abc942205a1a80584a288c262d03a in
 * the "quiche" repository.  (Not to be confused with Cloudflare's "quiche".)
 *
 * The BBR I-D is here:
 *  https://tools.ietf.org/html/draft-cardwell-iccrg-bbr-congestion-control-00
 *
 * As for quiche, see
 *  http://www.bernstein-plus-sons.com/RPDEQ.html
 *
 * Chromium copyright notice follows.
 */
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE.chrome file.

struct lsquic_bbr
{
    const struct lsquic_conn_public  *bbr_conn_pub;

    enum bbr_mode
    {
        BBR_MODE_STARTUP,
        BBR_MODE_DRAIN,
        BBR_MODE_PROBE_BW,
        BBR_MODE_PROBE_RTT,
    }                           bbr_mode;	/* bbr״̬��ģʽ */

    enum
    {
        BBR_RS_NOT_IN_RECOVERY,	/* �޶���, ����������BBR_RS_CONSERVATION */
        BBR_RS_CONSERVATION,	/* ����ģʽ, ������cwnd�Ҷ�����cwnd, ��������һ�ֺ����BBR_RS_GROWTH */
        BBR_RS_GROWTH,		/* ����������cwnd������Ҳ��cwnd, ����һ��û�ж����Ż�ص�BBR_RS_NOT_IN_RECOVERY */
    }                           bbr_recovery_state;	/* ���ٻָ�״̬ */

    enum
    {
        BBR_FLAG_IN_ACK                  = 1 << 0,   /* cci_begin_ack() has been called */
        BBR_FLAG_LAST_SAMPLE_APP_LIMITED = 1 << 1,	/* ACK����߰�����û��app limited */
        BBR_FLAG_HAS_NON_APP_LIMITED     = 1 << 2,	/* ��������û�б�app limited */
        BBR_FLAG_APP_LIMITED_SINCE_LAST_PROBE_RTT
                                         = 1 << 3,
        BBR_FLAG_PROBE_RTT_DISABLED_IF_APP_LIMITED
                                         = 1 << 4,
        BBR_FLAG_PROBE_RTT_SKIPPED_IF_SIMILAR_RTT
                                         = 1 << 5,
        BBR_FLAG_EXIT_STARTUP_ON_LOSS    = 1 << 6,
        BBR_FLAG_IS_AT_FULL_BANDWIDTH    = 1 << 7,	/* startup̽�⵽������(3�ִ���û��25%) */
        BBR_FLAG_EXITING_QUIESCENCE      = 1 << 8,
        BBR_FLAG_PROBE_RTT_ROUND_PASSED  = 1 << 9,
        BBR_FLAG_FLEXIBLE_APP_LIMITED    = 1 << 10,
        // If true, will not exit low gain mode until bytes_in_flight drops
        // below BDP or it's time for high gain mode.
        BBR_FLAG_DRAIN_TO_TARGET         = 1 << 11,
        // When true, expire the windowed ack aggregation values in STARTUP
        // when bandwidth increases more than 25%.
        BBR_FLAG_EXPIRE_ACK_AGG_IN_STARTUP
                                         = 1 << 12,
        // If true, use a CWND of 0.75*BDP during probe_rtt instead of 4
        // packets.
        BBR_FLAG_PROBE_RTT_BASED_ON_BDP  = 1 << 13,	/* ���ú�probe_rttģʽinflight��Ϊ0.75*BDP, ������4���� */
        // When true, pace at 1.5x and disable packet conservation in STARTUP.
        BBR_FLAG_SLOWER_STARTUP          = 1 << 14,
        // When true, add the most recent ack aggregation measurement during STARTUP.
        BBR_FLAG_ENABLE_ACK_AGG_IN_STARTUP
                                         = 1 << 15,
        // When true, disables packet conservation in STARTUP.
        BBR_FLAG_RATE_BASED_STARTUP      = 1 << 16, /* ���ú�startup�����ÿ��ٻָ���cwnd */
    }                           bbr_flags;

    // Number of round-trips in PROBE_BW mode, used for determining the current
    // pacing gain cycle.
    unsigned                    bbr_cycle_current_offset;	/* probe_bw���ڵ�pacing_gain���� */

    const struct lsquic_rtt_stats
                               *bbr_rtt_stats;

    struct bw_sampler           bbr_bw_sampler;	/* �����շ���ʱ�Ĵ���ȸ���ͳ�� */

    /*
     " BBR.BtlBwFilter: The max filter used to estimate BBR.BtlBw.
     */
    struct minmax               bbr_max_bandwidth;

    // Tracks the maximum number of bytes acked faster than the sending rate.
    struct minmax               bbr_max_ack_height;

    // The initial value of the bbr_cwnd.
    uint64_t                    bbr_init_cwnd;
    // The smallest value the bbr_cwnd can achieve.
    uint64_t                    bbr_min_cwnd;
    // The largest value the bbr_cwnd can achieve.
    uint64_t                    bbr_max_cwnd;
    // The maximum allowed number of bytes in flight.
    uint64_t                    bbr_cwnd;

    // The time this aggregation started and the number of bytes acked during it.
    lsquic_time_t               bbr_aggregation_epoch_start_time;
    uint64_t                    bbr_aggregation_epoch_bytes;

    lsquic_packno_t             bbr_last_sent_packno;	/* ���·��͵İ��� */
    lsquic_packno_t             bbr_current_round_trip_end;

    // Receiving acknowledgement of a packet after |bbr_end_recovery_at| will
    // cause BBR to exit the recovery mode.  A value above zero indicates at
    // least one loss has been detected, so it must not be set back to zero.
    lsquic_packno_t             bbr_end_recovery_at;

    /*
     " BBR.round_count: Count of packet-timed round trips.
     */
    uint64_t                    bbr_round_count;	/* ��ǰ���� */

    /* Not documented in the draft: */
    uint64_t                    bbr_full_bw;

    /* Not documented in the draft: */
    uint64_t                    bbr_full_bw_count;

    /*
     " BBR.pacing_rate: The current pacing rate for a BBR flow, which
     " controls inter-packet spacing.
     */
    struct bandwidth            bbr_pacing_rate;

    // Sum of bytes lost in STARTUP.
    uint64_t                    bbr_startup_bytes_lost;

    /*
     " BBR.pacing_gain: The dynamic gain factor used to scale BBR.BtlBw to
     " produce BBR.pacing_rate.
     */
    float                       bbr_pacing_gain;

    // The pacing gain applied during the STARTUP phase.
    float                       bbr_high_gain;

    // The CWND gain applied during the STARTUP phase.
    float                       bbr_high_cwnd_gain;

    // The pacing gain applied during the DRAIN phase.
    float                       bbr_drain_gain;

    // The number of RTTs to stay in STARTUP mode.  Defaults to 3.
    unsigned                    bbr_num_startup_rtts;

    // Number of rounds during which there was no significant bandwidth
    // increase.
    unsigned                    bbr_round_wo_bw_gain;

    /*
     " BBR.cwnd_gain: The dynamic gain factor used to scale the estimated
     " BDP to produce a congestion window (cwnd).
     */
    float                       bbr_cwnd_gain;

    // The bandwidth compared to which the increase is measured.
    struct bandwidth            bbr_bw_at_last_round;

    // The time at which the last pacing gain cycle was started.
    lsquic_time_t               bbr_last_cycle_start;

    // Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
    // that the time is yet unknown as the number of packets in flight has not
    // reached the required value.
    lsquic_time_t               bbr_exit_probe_rtt_at;

    lsquic_time_t               bbr_min_rtt_since_last_probe;
    lsquic_time_t               bbr_min_rtt;
    lsquic_time_t               bbr_min_rtt_timestamp;	/* bbr_min_rtt���µ�ʱ�� */

    // A window used to limit the number of bytes in flight during loss recovery
    uint64_t                    bbr_recovery_window;	/* ���ٻָ�(�ж���)ʱ��cwnd */

    /* Accumulate information from a single ACK.  Gets processed when
     * cci_end_ack() is called.
     */
    struct /* ������¼����ACK�ľ�������(ÿ��ACK����) */
    {
        TAILQ_HEAD(, bw_sample) samples;	/* ����ACKȷ�ϵ�ÿ��������õ���bw��rtt */
        lsquic_time_t       ack_time;		/* ����ACK����ʱ�� */
        lsquic_packno_t     max_packno;		/* ����ACKȷ�ϵ������� */
        uint64_t            acked_bytes;	/* ����ACKȷ�ϵ��ֽ��� */
        uint64_t            lost_bytes;		/* ����ACK��⵽�������ֽ��� */
        uint64_t            total_bytes_acked_before; /* ����ACK����ǰ����acked�ֽ��� */
        uint64_t            in_flight;		/* ����ACK����ǰ��inflight */
        int                 has_losses;		/* ����ACK�м�⵽���� */
    }                           bbr_ack_state;
};

extern const struct cong_ctl_if lsquic_cong_bbr_if;

#endif
