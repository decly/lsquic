/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_cong_ctl.h -- congestion control interface
 */

#ifndef LSQUIC_CONG_CTL_H
#define LSQUIC_CONG_CTL_H


struct lsquic_conn_public;
struct lsquic_packet_out;
enum quic_ft_bit;


/* All the methods don't quite match up between Cubic and BBR.  Thus, some of
 * the methods are optional; they are marked as such in the comments below.
 * Reconciling Cubic and BBR to have similar interface is left as an exercise
 * for the future.
 */
struct cong_ctl_if
{
    void
    (*cci_init) (void *cong_ctl, const struct lsquic_conn_public *,
                                                            enum quic_ft_bit);

    void
    (*cci_reinit) (void *cong_ctl);

    /* 针对被ACK的每个lsquic_packet_out调用
     * 调用顺序为: cci_begin_ack -> for each acked packet(cci_ack) -> cci_end_ack
     */
    void
    (*cci_ack) (void *cong_ctl, struct lsquic_packet_out *, unsigned packet_sz,
                lsquic_time_t now, int app_limited);

    /* 检测到新的丢包事件, 只有每次 snd.una > high_seq 时才会被调用,
     * 也就是类似tcp每次进入recovery状态
     * 而cci_lost()则是针对检测到每个丢包都会调用
     */
    void
    (*cci_loss) (void *cong_ctl);

    /* Optional method */
    /* 收到ACK处理前被调用 */
    void
    (*cci_begin_ack) (void *cong_ctl, lsquic_time_t ack_time,
                                                        uint64_t in_flight);

    /* Optional method */
    /* 收到ACK处理后被调用 */
    void
    (*cci_end_ack) (void *cong_ctl, uint64_t in_flight);

    /* Optional method */
    /* 发送时针对包调用 */
    void
    (*cci_sent) (void *cong_ctl, struct lsquic_packet_out *,
                                        uint64_t in_flight, int app_limited);

    /* Optional method */
    /* 检测到丢包时针对每个丢包调用 */
    void
    (*cci_lost) (void *cong_ctl, struct lsquic_packet_out *,
                                                        unsigned packet_sz);

    /* RTO触发时被调用 */
    void
    (*cci_timeout) (void *cong_ctl);

    void
    (*cci_was_quiet) (void *cong_ctl, lsquic_time_t now, uint64_t in_flight);

    /* 获取cwnd */
    uint64_t
    (*cci_get_cwnd) (void *cong_ctl);

    /* 获取pacing_rate */
    uint64_t
    (*cci_pacing_rate) (void *cong_ctl, int in_recovery);

    void
    (*cci_cleanup) (void *cong_ctl);
};

#endif
