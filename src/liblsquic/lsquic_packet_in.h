/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
/*
 * lsquic_packet_in.h
 */

#ifndef LSQUIC_PACKET_IN_H
#define LSQUIC_PACKET_IN_H 1


struct lsquic_packet_in;
struct lsquic_cid;


struct data_frame
{
    const unsigned char *df_data;       /* Pointer to data *//* 指向流帧中的数据 */
    uint64_t             df_offset;     /* Stream offset *//* 流数据偏移(type的0x04位) */
    uint16_t             df_read_off;   /* Read offset *//* 当前上层读取到该帧的偏移, 没有则是0 */
    uint16_t             df_size;       /* Size of df_data *//* 流帧中的数据长度(type的0x02位) */
    signed char          df_fin;        /* FIN? *//* FIN标志(设置了type的0x01位) */
};


typedef struct stream_frame /* 表示一个流帧(QUIC_FRAME_STREAM) */
{
    /* Stream frames are stored in a list inside "di nocopy" (if "di nocopy"
     * is used).
     */
    TAILQ_ENTRY(stream_frame)       next_frame;

    /* `data_frame.df_data' points somewhere into the packet payload.  The
     * packet object is reference-counted.  When the frame is freed, the
     * packet is released via lsquic_packet_in_put().
     */
    struct lsquic_packet_in        *packet_in;  /* 指向收到流帧对应的包 */

    struct data_frame               data_frame; /* 保留从流帧解析的各字段 */

    lsquic_stream_id_t stream_id;     /* Parsed from packet *//* 流帧中的流id */
} stream_frame_t;


#define DF_OFF(frame) (frame)->data_frame.df_offset
#define DF_ROFF(frame) (DF_OFF(frame) + (frame)->data_frame.df_read_off)
#define DF_FIN(frame) (frame)->data_frame.df_fin
#define DF_SIZE(frame) (frame)->data_frame.df_size
#define DF_END(frame) (DF_OFF(frame) + DF_SIZE(frame)) /* 帧的数据尾部偏移 */


typedef struct lsquic_packet_in /* 表示收到的包(一个UDP报文可能有多个lsquic_packet_in) */
{
    TAILQ_ENTRY(lsquic_packet_in)   pi_next;
    lsquic_time_t                   pi_received;   /* Time received *//* 包的接收时间 */
    lsquic_cid_t                    pi_dcid;       /* 目的cid */
#define pi_conn_id pi_dcid
    lsquic_packno_t                 pi_packno;     /* 包号
                                                    * 接收时一开始先初始化为一个非法值(1ULL << 62)
                                                    * 然后在 process_regular_packet()
                                                    *          ->iquic_esf_decrypt_packet()
                                                    *            ->strip_hp() 中解码
                                                    */
    enum quic_ft_bit                pi_frame_types;/* 数据包携带的帧类型, 按位或, 可能携带多种帧 */
    unsigned short                  pi_header_sz;  /* Points to payload *//* 包头大小 */
                                                   /* 最终都包括完整首部(包含到包号字段)
                                                    * 但是一开始解析过程中不包括包号(即只包括到包号字段之前),
                                                    * 等到包号解码后才包含包号(iquic_esf_decrypt_packet()中)
                                                    * 特例: retry/版本协商包包含了整个UDP报文(这两种包没有包号字段)
                                                    */
    unsigned short                  pi_data_sz;    /* Data plus header */
                                                   /* quic包大小, 包括包头和数据 */
    /* A packet may be referred to by one or more frames and packets_in
     * list.
     */
    unsigned short                  pi_refcnt;
    unsigned short                  pi_hsk_stream; /* Offset to handshake stream
                                                    * frame, only valid if
                                                    * PI_HSK_STREAM is set.
                                                    */
    enum {
        PI_DECRYPTED    = (1 << 0),                /* 表示数据包已经解码 */
        PI_OWN_DATA     = (1 << 1),                /* We own pi_data */
        PI_CONN_ID      = (1 << 2),                /* pi_conn_id is set */
                                                   /* 表示获取了目的cid(pi_dcid) */
        PI_HSK_STREAM   = (1 << 3),                /* Has handshake data (mini only) */
        PI_FROM_MINI    = (1 << 4),                /* Handed off by mini connection */
#define PIBIT_ENC_LEV_SHIFT 5                      /* 下面这两位是包加密的等级, 不同包类型等级不同
                                                    * 根据hety2el数组对应等级
                                                    */
        PI_ENC_LEV_BIT_0= (1 << 5),                /* Encodes encryption level */
        PI_ENC_LEV_BIT_1= (1 << 6),                /*  (see enum enc_level). */
        PI_GQUIC        = (1 << 7),                /* 表示gquic的数据包, 不设置即iquic */
        PI_UNUSED_8     = (1 << 8),                /* <-- hole, reuse me! */
#define PIBIT_ECN_SHIFT 9
        PI_ECN_BIT_0    = (1 << 9),                 /* 这两位为收到包的ECN标志(TOS字段的第6,7两位), 即ECT(6)和CE(7)位 */
        PI_ECN_BIT_1    = (1 <<10),                 /* ECT和CE位分别组成4种组合: 00(Not-ECT) 01(ECT1) 10(ECT0) 11(CE) */
#define PIBIT_SPIN_SHIFT 11
        PI_SPIN_BIT     = (1 <<11),                 /* 短包头中设置了自旋比特位(为1) */
#define PIBIT_BITS_SHIFT 12
        PI_BITS_BIT_0   = (1 <<12),                 /* 首字节的最低两位 */
        PI_BITS_BIT_1   = (1 <<13),                 /* 这两位在短包头中表示包号长度 */
        /* Square bit and loss bit flags are used for logging */
        PI_LOG_QL_BITS  = (1 <<14),
        PI_SQUARE_BIT   = (1 <<15),
        PI_LOSS_BIT     = (1 <<16),
        PI_VER_PARSED   = (1 <<17),                 /* 解析到quic版本, 保存到pi_version */
        PI_FIRST_INIT   = (1 <<18),                 /* 首个初始包 */
    }                               pi_flags;
    /* pi_token and pi_token_size are set in Initial and Retry packets */
    unsigned short                  pi_token_size; /* Size of the token */
                                                   /* initial/retry包携带的token(即pi_token)的长度 */
    unsigned short                  pi_pkt_size;   /* Size of the whole packet */
                                                   /* 整个UDP报文的大小, 即如果一个UDP报文中
                                                    * 有多个QUIC包也为整体UDP的大小
                                                    */
    unsigned char                   pi_token;      /* Offset to token */
                                                   /* initial/retry包携带的token在包中的偏移, 即pi_data + pi_token
                                                    * 没有则为0
                                                    */
    /* pi_odcid and pi_odcid_len are only set in Retry packets for I-D < 25 */
    unsigned char                   pi_odcid;      /* Offset to Original DCID */
    unsigned char                   pi_odcid_len;  /* Size of ODCID */
    unsigned char                   pi_scid_off;   /* Offset to SCID */
                                                   /* 源cid在数据中的偏移量, 即pi_data + pi_scid_off */
    unsigned char                   pi_scid_len;   /* Size of SCID */
                                                   /* 源cid的长度, cid的偏移量为pi_scid_off */
    unsigned char                   pi_quic_ver;   /* Offset to QUIC version */
                                                   /* 长包头为quic版本在包首部的偏移
                                                    * (特例:版本协商包指向携带的版本号)
                                                    * 短包头为0
                                                    */
    unsigned char                   pi_nonce;      /* Offset to nonce */
    enum header_type                pi_header_type:8; /* 长包头数据包类型: enum header_type
                                                       * 短包头初始化0
                                                       */
    unsigned char                   pi_path_id;    /* 该包的网络路径(v4/v6+四元组)对应连接ifc_paths中的索引 */
    unsigned char                   pi_version;    /* parsed enum lsquic_version */
                                                   /* quic的版本, 值为enum lsquic_version */
    /* If PI_OWN_DATA flag is not set, `pi_data' points to user-supplied
     * packet data, which is NOT TO BE MODIFIED.
     */
    unsigned char                  *pi_data;        /* 包的实体数据, 从包首部开始 */
} lsquic_packet_in_t;


#define lsquic_packet_in_public_flags(p) ((p)->pi_data[0])

#define lsquic_packet_in_is_gquic_prst(p) \
    (((p)->pi_flags & PI_GQUIC) \
        && (lsquic_packet_in_public_flags(p) & PACKET_PUBLIC_FLAGS_RST))

#define lsquic_packet_in_is_verneg(p) \
    (((p)->pi_flags & PI_GQUIC) ? \
        lsquic_packet_in_public_flags(p) & PACKET_PUBLIC_FLAGS_VERSION : \
        (p)->pi_header_type == HETY_VERNEG)

#define lsquic_packet_in_packno_bits(p) \
                        (((p)->pi_flags >> PIBIT_BITS_SHIFT) & 3)

#define lsquic_packet_in_upref(p) (++(p)->pi_refcnt)

#define lsquic_packet_in_get(p) (lsquic_packet_in_upref(p), (p))

#define lsquic_packet_in_nonce(p) \
                    ((p)->pi_nonce ? (p)->pi_data + (p)->pi_nonce : NULL)

#define lsquic_packet_in_enc_level(p) \
    (((p)->pi_flags >> PIBIT_ENC_LEV_SHIFT) & 0x3)

#define lsquic_packet_in_ecn(p) \
    (((p)->pi_flags >> PIBIT_ECN_SHIFT) & 0x3)

#define lsquic_packet_in_spin_bit(p) (((p)->pi_flags & PI_SPIN_BIT) > 0)

/* PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames
 * are "probing frames", and all other frames are "non-probing frames".
 * A packet containing only probing frames is a "probing packet", and a
 * packet containing any other frame is a "non-probing packet".
 *
 * [draft-ietf-quic-transport-20], Section 9.1
 */
#define lsquic_packet_in_non_probing(p) \
   (!!((p)->pi_frame_types & ~(QUIC_FTBIT_PATH_CHALLENGE                \
                        |QUIC_FTBIT_PATH_RESPONSE|QUIC_FTBIT_PADDING    \
                        |QUIC_FTBIT_NEW_CONNECTION_ID)))

/* The version iterator is used on a version negotiation packet only.
 * The iterator functions return 1 when next version is returned and
 * 0 when there are no more versions.
 */
struct ver_iter
{
    const struct lsquic_packet_in  *packet_in;
    unsigned                        off;
};

int
lsquic_packet_in_ver_first (const lsquic_packet_in_t *packet_in,
                            struct ver_iter *, lsquic_ver_tag_t *ver_tag);

int
lsquic_packet_in_ver_next (struct ver_iter *, lsquic_ver_tag_t *ver_tag);

size_t
lsquic_packet_in_mem_used (const struct lsquic_packet_in *);

void
lsquic_scid_from_packet_in (const struct lsquic_packet_in *,
                                                    struct lsquic_cid *);

#endif
