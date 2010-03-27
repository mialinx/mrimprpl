#include <glib.h>
#include <string.h>
#include "pkt.h"

typedef struct {
    guint32 length;
    gchar data[];
} MrimPktLps;

#define MRIM_PKT_TOTAL_LEN(pkt) (GUINT32_FROM_LE(pkt->dlen) + sizeof(MrimPktHeader))
#define MRIM_PKT_LPS_LEN(lps) (GUINT32_FROM_LE((lps)->length) + sizeof((lps)->length))

/* Client to Server messages */
static void
_mrim_pkt_init_header(MrimPktHeader *header, guint32 seq, guint32 msg, guint32 dlen)
{
    header->magic = GUINT32_TO_LE(CS_MAGIC);
    header->proto = GUINT32_TO_LE(PROTO_VERSION);
    header->seq = GUINT32_TO_LE(seq);
    header->msg = GUINT32_TO_LE(msg);
    header->dlen = GUINT32_TO_LE(dlen);
    header->from = GUINT32_TO_LE(0x00000000);
    header->fromport = GUINT32_TO_LE(0x00000000);
    memset(header->reserved, '\0', 16);
}

static MrimPktLps *
_mrim_pkt_str2lps(gchar *str)
{
    guint32 len = 0;
    gchar *conv = NULL;
    guint32 conv_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    MrimPktLps *lps = NULL;
    GError *err = NULL;

    len = strlen(str);
    g_get_charset(&local_charset);
    conv = g_convert(str, len, "WINDOWS-1251", local_charset, NULL, &conv_len, &err);
    if (!conv) {
        fprintf(stderr, "FAILED STR2LPS: bad encoding %s\n", err->message);
        return NULL;
    }

    lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + conv_len);
    lps->length = GUINT32_TO_LE(conv_len);
    memcpy(lps->data, conv, conv_len);
    g_free(conv);
    return lps;
}

void
mrim_pkt_build_hello(MrimData *md) 
{
    MrimPktHeader header;
    _mrim_pkt_init_header(&header, 0, MRIM_CS_HELLO, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}

void
mrim_pkt_build_login(MrimData *md, gchar *login, gchar *pass,
                    guint32 status, gchar *agent)
{
    MrimPktLps *lps_login = NULL, *lps_pass = NULL, *lps_agent = NULL;
    MrimPktHeader header;
    guint32 dlen = 0;

    if (!(lps_login = _mrim_pkt_str2lps(login))) {
        return;
    }
    if (!(lps_pass = _mrim_pkt_str2lps(pass))) {
        g_free(lps_login);
        return;
    }
    status = GUINT32_TO_LE(status);
    if (!(lps_agent = _mrim_pkt_str2lps(agent))) {
        g_free(lps_login);
        g_free(lps_pass);
        return;
    }

    dlen = MRIM_PKT_LPS_LEN(lps_login) + MRIM_PKT_LPS_LEN(lps_pass) +
            sizeof(dlen) + MRIM_PKT_LPS_LEN(lps_agent);

    _mrim_pkt_init_header(&header, 0, MRIM_CS_LOGIN2, dlen);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_login, MRIM_PKT_LPS_LEN(lps_login));
    purple_circ_buffer_append(md->server.tx_buf, lps_pass, MRIM_PKT_LPS_LEN(lps_pass));
    purple_circ_buffer_append(md->server.tx_buf, &status, sizeof(status));
    purple_circ_buffer_append(md->server.tx_buf, lps_agent, MRIM_PKT_LPS_LEN(lps_agent));
    g_free(lps_login);
    g_free(lps_pass);
    g_free(lps_agent);

    return;
}

void
mrim_pkt_build_ping(MrimData *md)
{
    MrimPktHeader header;
    _mrim_pkt_init_header(&header, 0, MRIM_CS_PING, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}


/* Server to Client messages */

/* Collect bytes in rx_pkt_buf for just one packet 
   Returns NULL if there are not sufficient bytes in circle buffer
*/

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

    switch (GUINT32_FROM_LE(pkt->msg)) {
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
                (guint) GUINT32_FROM_LE(pkt->msg));
            #endif
            break;
            
    }
    /* twice space will be sufficient for utf8 encoding */
    loc = (MrimPktHeader *)g_malloc0(MRIM_PKT_TOTAL_LEN(pkt) * 2);
    
    loc->magic = GUINT32_FROM_LE(pkt->magic);
    loc->proto = GUINT32_FROM_LE(pkt->proto);
    loc->seq = GUINT32_FROM_LE(pkt->seq);
    loc->msg = GUINT32_FROM_LE(pkt->msg);
    loc->dlen = GUINT32_FROM_LE(pkt->dlen);

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
