#include <glib.h>
#include <string.h>
#include "pkt.h"

/* Common utils */

#define MRIM_PKT_PKT_LEN(pkt) (GUINT32_FROM_LE(pkt->dlen) + sizeof(MrimPktHeader))
#define MRIM_PKT_LPS_LEN(lps) (GUINT32_FROM_LE((lps)->length) + sizeof((lps)->length))

typedef struct {
    guint32 length;
    gchar data[];
} MrimPktLps;

static MrimPktLps *
_str2lps(const gchar *str)
{
    gchar *data = NULL;
    guint32 data_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    MrimPktLps *lps = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);
    data = g_convert(str, strlen(str), "WINDOWS-1251", local_charset, NULL, &data_len, &err);
    if (!data) {
        fprintf(stderr, "FAILED STR2LPS: bad encoding %s\n", err->message);
        return NULL;
    }

    lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + data_len);
    lps->length = GUINT32_TO_LE(data_len);
    memcpy(lps->data, data, data_len);
    g_free(data);
    return lps;
}

static gchar *
_lps2str(MrimPktLps *lps)
{
    gchar *str = NULL;
    guint32 str_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);
    str = g_convert(lps->data, lps->length, local_charset, "WINDOWS-1251", NULL, &str_len, &err);
    if (!str) {
        fprintf(stderr, "FAILED STR2LPS: bad encoding %s\n", err->message);
        return NULL;
    }

    return str;
}

/* Client to Server messages */

static void
_init_header(MrimPktHeader *header, guint32 seq, guint32 msg, guint32 dlen)
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

void
mrim_pkt_build_hello(MrimData *md) 
{
    MrimPktHeader header;
    _init_header(&header, ++md->tx_seq, MRIM_CS_HELLO, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}

void
mrim_pkt_build_login(MrimData *md, const gchar *login, const gchar *pass,
                    guint32 status, const gchar *agent)
{
    MrimPktLps *lps_login = NULL, *lps_pass = NULL, *lps_agent = NULL;
    MrimPktHeader header;
    guint32 dlen = 0;

    if (!(lps_login = _str2lps(login))) {
        return;
    }
    if (!(lps_pass = _str2lps(pass))) {
        g_free(lps_login);
        return;
    }
    status = GUINT32_TO_LE(status);
    if (!(lps_agent = _str2lps(agent))) {
        g_free(lps_login);
        g_free(lps_pass);
        return;
    }

    dlen = MRIM_PKT_LPS_LEN(lps_login) + MRIM_PKT_LPS_LEN(lps_pass) +
            sizeof(dlen) + MRIM_PKT_LPS_LEN(lps_agent);

    _init_header(&header, ++md->tx_seq, MRIM_CS_LOGIN2, dlen);
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
    _init_header(&header, ++md->tx_seq, MRIM_CS_PING, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}


/* Server to Client messages */

/* Collect bytes in rx_pkt_buf for just one packet 
   Returns NULL if there are not sufficient bytes in circle buffer
*/

static MrimPktHeader *
_collect(MrimData *md)
{
    guint available = 0;
    gint need_read = 0;
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
/* BUG IS HERE */
    /* copy whole packet to the linear buffer */
    while ((need_read = MRIM_PKT_PKT_LEN(pkt) - md->server.rx_pkt_buf->len) > 0) {
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

static void
_read_header(MrimPktHeader *pkt, MrimPktHeader *loc, guint32 *pos)
{
    loc->magic = GUINT32_FROM_LE(pkt->magic);
    loc->proto = GUINT32_FROM_LE(pkt->proto);
    loc->seq = GUINT32_FROM_LE(pkt->seq);
    loc->msg = GUINT32_FROM_LE(pkt->msg);
    loc->dlen = GUINT32_FROM_LE(pkt->dlen);
    memcpy(loc->reserved, pkt->reserved, 16);
    *pos += sizeof(MrimPktHeader);
}

static guint32
_read_ul(MrimPktHeader *pkt, guint32 *pos)
{
    guint32 val = *( (guint32*) (((gchar*)pkt) + *pos) );
    *pos += sizeof(guint32);
    return val;
}

static gchar *
_read_lps(MrimPktHeader *pkt, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (((gchar*)pkt) + *pos);
    *pos += MRIM_PKT_LPS_LEN(lps);
    return _lps2str(lps);
}

MrimPktHeader *
mrim_pkt_parse(MrimData *md)
{
    MrimPktHeader *loc = NULL;
    MrimPktHeader *pkt = NULL;
    guint32 pos = 0;
    gchar *tmp = NULL, *tmp2 = NULL;

    if (!(pkt = _collect(md))) {
        return NULL;
    }

fprintf(stderr, "MSG %x\n", GUINT32_FROM_LE(pkt->msg));

    switch (GUINT32_FROM_LE(pkt->msg)) {
        case MRIM_CS_HELLO_ACK:
            /* twice space will be sufficient for utf8 encoding */
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktHelloAck));
            _read_header(pkt, loc, &pos);
            ((MrimPktHelloAck *)loc)->timeout = _read_ul(pkt, &pos);
            break;
        case MRIM_CS_LOGIN_ACK:
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktLoginAck));
            _read_header(pkt, loc, &pos);
            break;
        case MRIM_CS_LOGIN_REJ:
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktLoginRej));
            _read_header(pkt, loc, &pos);
            ((MrimPktLoginRej *)loc)->reason = _read_lps(pkt, &pos);
            break;
        case MRIM_CS_MESSAGE_ACK:
            break;
        case MRIM_CS_MESSAGE_STATUS:
            break;
        case MRIM_CS_USER_STATUS:
            break;
        case MRIM_CS_LOGOUT:
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktLogout));
            ((MrimPktLogout*)loc)->reason = _read_ul(pkt, &pos);
            break;
        case MRIM_CS_CONNECTION_PARAMS:
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktConnectionParam));
            _read_header(pkt, loc, &pos);
            ((MrimPktConnectionParam *)loc)->timeout = _read_ul(pkt, &pos);
            break;
        case MRIM_CS_USER_INFO:
            loc = (MrimPktHeader *) g_malloc0(sizeof(MrimPktUserInfo));
            ((MrimPktUserInfo *)loc)->info = g_hash_table_new_full(NULL, NULL, g_free, g_free);
            _read_header(pkt, loc, &pos);
            while (pos < loc->dlen) {
                tmp = _read_lps(pkt, &pos);
                tmp2 = _read_lps(pkt, &pos);
                g_hash_table_insert(((MrimPktUserInfo *)loc)->info, tmp, tmp2);
            }
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
                g_free(pkt);
                break;
            case MRIM_CS_CONNECTION_PARAMS:
                g_free(pkt);
                break;
            case MRIM_CS_USER_INFO:
                g_hash_table_destroy(((MrimPktUserInfo *)pkt)->info);
                g_free(pkt);
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
