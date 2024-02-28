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
    const unsigned char *df_data;       /* Pointer to data *//* ָ����֡�е����� */
    uint64_t             df_offset;     /* Stream offset *//* ������ƫ��(type��0x04λ) */
    uint16_t             df_read_off;   /* Read offset *//* ��ǰ�ϲ��ȡ����֡��ƫ��, û������0 */
    uint16_t             df_size;       /* Size of df_data *//* ��֡�е����ݳ���(type��0x02λ) */
    signed char          df_fin;        /* FIN? *//* FIN��־(������type��0x01λ) */
};


typedef struct stream_frame /* ��ʾһ����֡(QUIC_FRAME_STREAM) */
{
    /* Stream frames are stored in a list inside "di nocopy" (if "di nocopy"
     * is used).
     */
    TAILQ_ENTRY(stream_frame)       next_frame;

    /* `data_frame.df_data' points somewhere into the packet payload.  The
     * packet object is reference-counted.  When the frame is freed, the
     * packet is released via lsquic_packet_in_put().
     */
    struct lsquic_packet_in        *packet_in;  /* ָ���յ���֡��Ӧ�İ� */

    struct data_frame               data_frame; /* ��������֡�����ĸ��ֶ� */

    lsquic_stream_id_t stream_id;     /* Parsed from packet *//* ��֡�е���id */
} stream_frame_t;


#define DF_OFF(frame) (frame)->data_frame.df_offset
#define DF_ROFF(frame) (DF_OFF(frame) + (frame)->data_frame.df_read_off)
#define DF_FIN(frame) (frame)->data_frame.df_fin
#define DF_SIZE(frame) (frame)->data_frame.df_size
#define DF_END(frame) (DF_OFF(frame) + DF_SIZE(frame)) /* ֡������β��ƫ�� */


typedef struct lsquic_packet_in /* ��ʾ�յ��İ�(һ��UDP���Ŀ����ж��lsquic_packet_in) */
{
    TAILQ_ENTRY(lsquic_packet_in)   pi_next;
    lsquic_time_t                   pi_received;   /* Time received *//* ���Ľ���ʱ�� */
    lsquic_cid_t                    pi_dcid;       /* Ŀ��cid */
#define pi_conn_id pi_dcid
    lsquic_packno_t                 pi_packno;     /* ����
                                                    * ����ʱһ��ʼ�ȳ�ʼ��Ϊһ���Ƿ�ֵ(1ULL << 62)
                                                    * Ȼ���� process_regular_packet()
                                                    *          ->iquic_esf_decrypt_packet()
                                                    *            ->strip_hp() �н���
                                                    */
    enum quic_ft_bit                pi_frame_types;/* ���ݰ�Я����֡����, ��λ��, ����Я������֡ */
    unsigned short                  pi_header_sz;  /* Points to payload *//* ��ͷ��С */
                                                   /* ���ն����������ײ�(�����������ֶ�)
                                                    * ����һ��ʼ���������в���������(��ֻ�����������ֶ�֮ǰ),
                                                    * �ȵ����Ž����Ű�������(iquic_esf_decrypt_packet()��)
                                                    * ����: retry/�汾Э�̰�����������UDP����(�����ְ�û�а����ֶ�)
                                                    */
    unsigned short                  pi_data_sz;    /* Data plus header */
                                                   /* quic����С, ������ͷ������ */
    /* A packet may be referred to by one or more frames and packets_in
     * list.
     */
    unsigned short                  pi_refcnt;
    unsigned short                  pi_hsk_stream; /* Offset to handshake stream
                                                    * frame, only valid if
                                                    * PI_HSK_STREAM is set.
                                                    */
    enum {
        PI_DECRYPTED    = (1 << 0),                /* ��ʾ���ݰ��Ѿ����� */
        PI_OWN_DATA     = (1 << 1),                /* We own pi_data */
        PI_CONN_ID      = (1 << 2),                /* pi_conn_id is set */
                                                   /* ��ʾ��ȡ��Ŀ��cid(pi_dcid) */
        PI_HSK_STREAM   = (1 << 3),                /* Has handshake data (mini only) */
        PI_FROM_MINI    = (1 << 4),                /* Handed off by mini connection */
#define PIBIT_ENC_LEV_SHIFT 5                      /* ��������λ�ǰ����ܵĵȼ�, ��ͬ�����͵ȼ���ͬ
                                                    * ����hety2el�����Ӧ�ȼ�
                                                    */
        PI_ENC_LEV_BIT_0= (1 << 5),                /* Encodes encryption level */
        PI_ENC_LEV_BIT_1= (1 << 6),                /*  (see enum enc_level). */
        PI_GQUIC        = (1 << 7),                /* ��ʾgquic�����ݰ�, �����ü�iquic */
        PI_UNUSED_8     = (1 << 8),                /* <-- hole, reuse me! */
#define PIBIT_ECN_SHIFT 9
        PI_ECN_BIT_0    = (1 << 9),                 /* ����λΪ�յ�����ECN��־(TOS�ֶεĵ�6,7��λ), ��ECT(6)��CE(7)λ */
        PI_ECN_BIT_1    = (1 <<10),                 /* ECT��CEλ�ֱ����4�����: 00(Not-ECT) 01(ECT1) 10(ECT0) 11(CE) */
#define PIBIT_SPIN_SHIFT 11
        PI_SPIN_BIT     = (1 <<11),                 /* �̰�ͷ����������������λ(Ϊ1) */
#define PIBIT_BITS_SHIFT 12
        PI_BITS_BIT_0   = (1 <<12),                 /* ���ֽڵ������λ */
        PI_BITS_BIT_1   = (1 <<13),                 /* ����λ�ڶ̰�ͷ�б�ʾ���ų��� */
        /* Square bit and loss bit flags are used for logging */
        PI_LOG_QL_BITS  = (1 <<14),
        PI_SQUARE_BIT   = (1 <<15),
        PI_LOSS_BIT     = (1 <<16),
        PI_VER_PARSED   = (1 <<17),                 /* ������quic�汾, ���浽pi_version */
        PI_FIRST_INIT   = (1 <<18),                 /* �׸���ʼ�� */
    }                               pi_flags;
    /* pi_token and pi_token_size are set in Initial and Retry packets */
    unsigned short                  pi_token_size; /* Size of the token */
                                                   /* initial/retry��Я����token(��pi_token)�ĳ��� */
    unsigned short                  pi_pkt_size;   /* Size of the whole packet */
                                                   /* ����UDP���ĵĴ�С, �����һ��UDP������
                                                    * �ж��QUIC��ҲΪ����UDP�Ĵ�С
                                                    */
    unsigned char                   pi_token;      /* Offset to token */
                                                   /* initial/retry��Я����token�ڰ��е�ƫ��, ��pi_data + pi_token
                                                    * û����Ϊ0
                                                    */
    /* pi_odcid and pi_odcid_len are only set in Retry packets for I-D < 25 */
    unsigned char                   pi_odcid;      /* Offset to Original DCID */
    unsigned char                   pi_odcid_len;  /* Size of ODCID */
    unsigned char                   pi_scid_off;   /* Offset to SCID */
                                                   /* Դcid�������е�ƫ����, ��pi_data + pi_scid_off */
    unsigned char                   pi_scid_len;   /* Size of SCID */
                                                   /* Դcid�ĳ���, cid��ƫ����Ϊpi_scid_off */
    unsigned char                   pi_quic_ver;   /* Offset to QUIC version */
                                                   /* ����ͷΪquic�汾�ڰ��ײ���ƫ��
                                                    * (����:�汾Э�̰�ָ��Я���İ汾��)
                                                    * �̰�ͷΪ0
                                                    */
    unsigned char                   pi_nonce;      /* Offset to nonce */
    enum header_type                pi_header_type:8; /* ����ͷ���ݰ�����: enum header_type
                                                       * �̰�ͷ��ʼ��0
                                                       */
    unsigned char                   pi_path_id;    /* �ð�������·��(v4/v6+��Ԫ��)��Ӧ����ifc_paths�е����� */
    unsigned char                   pi_version;    /* parsed enum lsquic_version */
                                                   /* quic�İ汾, ֵΪenum lsquic_version */
    /* If PI_OWN_DATA flag is not set, `pi_data' points to user-supplied
     * packet data, which is NOT TO BE MODIFIED.
     */
    unsigned char                  *pi_data;        /* ����ʵ������, �Ӱ��ײ���ʼ */
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
