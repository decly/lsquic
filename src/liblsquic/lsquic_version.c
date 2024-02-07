/* Copyright (c) 2017 - 2022 LiteSpeed Technologies Inc.  See LICENSE. */
#include <string.h>

#include "lsquic.h"
#include "lsquic_int_types.h"
#include "lsquic_version.h"

#if _MSC_VER
#include "vc_compat.h"
#endif


static const unsigned char version_tags[N_LSQVER][4] =
{
    [LSQVER_043] = { 'Q', '0', '4', '3', },
    [LSQVER_046] = { 'Q', '0', '4', '6', },
    [LSQVER_050] = { 'Q', '0', '5', '0', },
    [LSQVER_ID27] = { 0xFF, 0, 0, 27, },
    [LSQVER_ID29] = { 0xFF, 0, 0, 29, },
    [LSQVER_I001] = {    0, 0, 0, 1, },
    [LSQVER_I002] = { 0x6B, 0x33, 0x43, 0xCF },
    [LSQVER_RESVED] = { 0xFA, 0xFA, 0xFA, 0xFA, },
};


uint32_t
lsquic_ver2tag (unsigned version)
{
    lsquic_ver_tag_t tag;
    if (version < N_LSQVER)
    {
        memcpy(&tag, version_tags[version], 4);
        return tag;
    }
    else
        return 0;
}


enum lsquic_version
lsquic_tag2ver (uint32_t ver_tag)
{
    unsigned n;
    for (n = 0; n < sizeof(version_tags) / sizeof(version_tags[0]); ++n)
        if (0 == memcmp(version_tags[n], &ver_tag, sizeof(ver_tag)))
            return n;
    return -1;
}

/* 从四字节的版本号中解析quic版本 */
enum lsquic_version
lsquic_tag2ver_fast (const unsigned char *tag)
{
    unsigned char ch;
    ch = *tag;
    if (ch == 'Q' && *(tag + 1) == '0')
    {
        if (*(tag + 2) == '5' && *(tag + 3) == '0')
            return LSQVER_050;
        else if (*(tag + 2) == '4' && *(tag + 3) == '6')
            return LSQVER_046;
        /* Q043的格式不一样, 没在这里检查 */
    }
    else if (ch == 0x6b && *(tag + 1) == 0x33
             && *(tag + 2) == 0x43 && *(tag + 3) == 0xcf)
    {
        return LSQVER_I002; /* iquic v2: 0x0b3343cf */
    }
    else if (ch == '\0' && *(tag + 1) == 0 && *(tag + 2) == 0)
    {
        if (*(tag + 3) == 0x01)
            return LSQVER_I001; /* iquic v1: 0x00000001 */
        else if (*(tag + 3) == 0x00)
            return LSQVER_VERNEG; /* 全0位版本协商 */
    }
    else if (ch == 0xff && *(tag + 1) == 0 && *(tag + 2) == 0)
    {
        if (*(tag + 3) == 0x1D)
            return LSQVER_ID29;
        else if (*(tag + 3) == 0x1B)
            return LSQVER_ID27;
    }
    else if ((ch & 0xf) == 0xa && (*(tag + 1) & 0xf) == 0xa
            && (*(tag + 2) & 0xf) == 0xa && (*(tag + 3) & 0xf) == 0xa)
        return LSQVER_RESVED; /* 保留标识, 即所有字节的低4位都为1010, 即0x?a?a?a?a */
    return N_LSQVER;
}


const char *const lsquic_ver2str[N_LSQVER] = {
    [LSQVER_043] = "Q043",
    [LSQVER_046] = "Q046",
    [LSQVER_050] = "Q050",
    [LSQVER_ID27] = "FF00001B",
    [LSQVER_ID29] = "FF00001D",
    [LSQVER_I001] = "00000001",
    [LSQVER_I002] = "6B3343CF",
    [LSQVER_RESVED] = "FAFAFAFA",
};


const char *const lsquic_ver2altstr[N_LSQVER] = {
    [LSQVER_043] = NULL,
    [LSQVER_046] = NULL,
    [LSQVER_050] = NULL,
    [LSQVER_ID27] = "h3-27",
    [LSQVER_ID29] = "h3-29",
    [LSQVER_I001] = "h3",
    [LSQVER_I002] = "h3-v2",
    [LSQVER_RESVED] = "RESERVED",
};


enum lsquic_version
lsquic_str2ver (const char *str, size_t len)
{
    enum lsquic_version ver;
    uint32_t tag;

    if (len == sizeof(tag) && 'Q' == str[0])
    {
        memcpy(&tag, str, sizeof(tag));
        return lsquic_tag2ver(tag);
    }

    for (ver = 0; ver < N_LSQVER; ++ver)
    {
        if (strlen(lsquic_ver2str[ver]) == len
            && strncasecmp(lsquic_ver2str[ver], str, len) == 0)
        {
            return ver;
        }
        if (lsquic_ver2altstr[ver] && strlen(lsquic_ver2altstr[ver]) == len
            && strncasecmp(lsquic_ver2altstr[ver], str, len) == 0)
        {
            return ver;
        }
    }
    return -1;
}


int
lsquic_gen_ver_tags (unsigned char *buf, size_t bufsz, unsigned version_bitmask)
{
    unsigned n;
    lsquic_ver_tag_t tag;
    unsigned char *p = buf;
    unsigned char *const pend = p + bufsz;
    for (n = 0; version_bitmask; ++n)
    {
        if (version_bitmask & (1 << n))
        {
            if (p + 4 > pend)
                return -1;
            version_bitmask &= ~(1 << n);
            tag = lsquic_ver2tag(n);
            if (0 == tag)
                return -1;
            memcpy(p, &tag, 4);
            p += 4;
        }
    }
    return p - buf;
}
