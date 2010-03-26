#include <glib.h>
#include <string.h>
#include "pkt.h"


/* Client to Server messages */

#define MRIM_PKT_INIT_HEADER(seq, msg, dlen)    \
    {                                           \
        GUINT32_TO_BE(CS_MAGIC),                \
        GUINT32_TO_BE(PROTO_VERSION),           \
        GUINT32_TO_BE((seq)),                   \
        GUINT32_TO_BE((msg)),                   \
        GUINT32_TO_BE((dlen)),                  \
        0, 0,                                   \
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"      \
    }
 
typedef struct {
    guint32 length;
    gchar *data;
} MrimPktLps;

static MrimPktLps *
_mrim_pkt_str2lps(gchar *str)
{
    guint32 len = 0;
    gchar *conv = NULL;
    guint32 conv_len = 0;
    G_CONST_RETURN char *enc = NULL;
    MrimPktLps *lps = NULL;

    len = strlen(str);
    g_get_charset(&enc);
    conv = g_convert(str, len, "ru_RU.CP1251", enc, NULL, &conv_len, NULL);
    if (!conv) {
        // TODO: error reporting
        fprintf(stderr, "FAILED STR2LPS: bad encoding\n");
        return NULL;
    }
    lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + conv_len);
    lps->length = GUINT32_TO_BE(conv_len);
    memcpy(lps->data, conv, conv_len);
    g_free(conv);
    return lps;
}

void
mrim_pkt_build_hello(MrimData *md) 
{
    MrimPktHeader header = MRIM_PKT_INIT_HEADER(0, MRIM_CS_HELLO, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}

void
mrim_pkt_build_login(MrimData *md, gchar *login, gchar *pass,
                    guint32 status, gchar *agent)
{
    MrimPktHeader header = MRIM_PKT_INIT_HEADER(0, MRIM_CS_LOGIN2, 0);

    MrimPktLps *lps_login = NULL, *lps_pass = NULL, *lps_agent = NULL;
    if (!(lps_login = _mrim_pkt_str2lps(login))) {
        return;
    }
    
FREE_LPS_LOGIN:
    g_free(lps_login);
FREE_LPS_PASS:
    g_free(lps_pass);
FREE_LPS_AGENT:
    g_free(lps_agent);
    return;
}

void
mrim_pkt_build_ping(MrimData *md)
{
    MrimPktHeader header = MRIM_PKT_INIT_HEADER(0, MRIM_CS_PING, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}


/* Server to Client messages */

/* Collect bytes in rx_pkt_buf for just one packet 
   Returns NULL if there are not sufficient bytes in circle buffer
*/

#define MRIM_PKT_TOTAL_LEN(pkt) (GUINT32_FROM_BE(pkt->dlen) + sizeof(MrimPktHeader))

MrimPktHeader *
_mrim_pkt_collect(MrimData *md)
{
    guint available = 0;
    guint need_read = 0;
    MrimPktHeader *pkt = NULL;

    /* copy complete packet header to the linear buffer */
    while ((need_read = sizeof(MrimPktHeader) - md->server.rx_pkt_buf->len) > 0) {
        if (!(available = purple_circ_buffer_get_max_read(md->server.rx_buf))) {
            return NULL;
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                MIN(need_read, available) 
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, MIN(need_read, available));
        }
    }
    pkt = (MrimPktHeader*) md->server.rx_pkt_buf->str;

    /* copy whole packet to the linear buffer */
    while ((need_read = MRIM_PKT_TOTAL_LEN(pkt) - md->server.rx_pkt_buf->len) > 0) {
        if (!(available = purple_circ_buffer_get_max_read(md->server.rx_buf))) {
            return NULL;
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                MIN(need_read, available)
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, MIN(need_read, available));
        }
    }

    /* ok, now we have complete packet. copy it and empty buffer */
    pkt = g_memdup(md->server.rx_pkt_buf->str, md->server.rx_pkt_buf->len);
    g_string_truncate(md->server.rx_pkt_buf, 0);

    return pkt;
}

MrimPktHeader *
mrim_pkt_parse(MrimData *md)
{
    MrimPktHeader *loc = NULL;
    MrimPktHeader *pkt = NULL;

    if (!(pkt = _mrim_pkt_collect(md))) {
        return NULL;
    }

    switch (GUINT32_FROM_BE(pkt->msg)) {
        case MRIM_CS_HELLO_ACK:
            break;
        case MRIM_CS_LOGIN_ACK:
            break;
        case MRIM_CS_LOGIN_REJ:
            break;
        case MRIM_CS_MESSAGE_ACK:
            break;
        case MRIM_CS_MESSAGE_STATUS:
            break;
        case MRIM_CS_USER_STATUS:
            break;
        case MRIM_CS_LOGOUT:
            break;
        case MRIM_CS_CONNECTION_PARAMS:
            break;
        case MRIM_CS_USER_INFO:
            break;
        case MRIM_CS_ADD_CONTACT_ACK:
            break;
        case MRIM_CS_MODIFY_CONTACT_ACK:
            break;
        case MRIM_CS_OFFLINE_MESSAGE_ACK:
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            break;
        case MRIM_CS_MPOP_SESSION:
            break;
        default:
            #ifdef ENABLE_MRIM_DEBUG
            purple_debug_info("mrim", "parsing unsupported type of packet %u\n", 
                (guint) GUINT32_FROM_BE(pkt->msg));
            #endif
            break;
            
    }
    /* twice space will be sufficient for utf8 encoding */
    loc = (MrimPktHeader *)g_malloc0(MRIM_PKT_TOTAL_LEN(pkt) * 2);
    
    loc->magic = GUINT32_FROM_BE(pkt->magic);
    loc->proto = GUINT32_FROM_BE(pkt->proto);
    loc->seq = GUINT32_FROM_BE(pkt->seq);
    loc->msg = GUINT32_FROM_BE(pkt->msg);
    loc->dlen = GUINT32_FROM_BE(pkt->dlen);

    /* TODO heere */

    g_free(pkt);
    return loc;
}

void
mrim_pkt_free(MrimPktHeader *pkt) 
{
    if (pkt) {
        switch (pkt->msg) {
            case MRIM_CS_HELLO_ACK:
                g_free(pkt);
                break;
            case MRIM_CS_LOGIN_ACK:
                g_free(pkt);
                break;
            case MRIM_CS_LOGIN_REJ:
                g_free(((MrimPktLoginRej *)pkt)->reason);
                g_free(pkt);
                break;
            case MRIM_CS_MESSAGE_ACK:
                break;
            case MRIM_CS_MESSAGE_STATUS:
                break;
            case MRIM_CS_USER_STATUS:
                break;
            case MRIM_CS_LOGOUT:
                break;
            case MRIM_CS_CONNECTION_PARAMS:
                break;
            case MRIM_CS_USER_INFO:
                break;
            case MRIM_CS_ADD_CONTACT_ACK:
                break;
            case MRIM_CS_MODIFY_CONTACT_ACK:
                break;
            case MRIM_CS_OFFLINE_MESSAGE_ACK:
                break;
            case MRIM_CS_AUTHORIZE_ACK:
                break;
            case MRIM_CS_MPOP_SESSION:
                break;
            default:
                #ifdef ENABLE_MRIM_DEBUG
                purple_debug_info("mrim", "freeing unsupported type of packet %u\n", 
                    (guint) pkt->msg);
                #endif
                break;
        }
    }
}
