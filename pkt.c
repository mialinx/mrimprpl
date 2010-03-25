#include <glib.h>
#include <string.h>
#include "pkt.h"

/*
static gchar *
mrim_pkt_lps2str(MrimPktLps *lps) 
{
    return g_strndup(lps->data, lps->length);
}

static MrimPktLps *
mrim_pkt_str2lps(const gchar *str)
{
    guint32 length = strlen(str);
    MrimPktLps *lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + length);
    lps->length = length;
    memcpy(lps->data, str, length);
    return lps;
}
*/

/* Common routines */

void
mrim_pkt_free(MrimPktLocal *pkt) 
{
    if (pkt) {
        switch (pkt->msg) {
            case MRIM_CS_HELLO_ACK:
                g_free(pkt);
                break;
            case MRIM_CS_LOGIN_ACK:
                g_free(pkt);
                break;
            case MRIM_CS_LOGIN_REJ;
                g_free(((MrimPktLoginRej)pkt).reason);
                g_free(pkt);
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

/* Client to Server messages */

static void
mrim_pkt_init_header(MrimPktHeader *pkt, guint32 seq, guint32 msg, guint32 dlen) 
{
    pkt->magic = GUINT32_TO_BE(CS_MAGIC);
    pkt->proto = GUINT32_TO_BE(PROTO_VERSION);
    pkt->seq = GUINT32_TO_BE(seq);
    pkt->msg = GUINT32_TO_BE(msg);
    pkt->dlen = GUINT32_TO_BE(dlen);
}

void
mrim_pkt_build_hello(MrimData *md) 
{
    MrimPktHeader *pkt = (MrimPktHeader*) g_malloc0(sizeof(MrimPktCsHello));
    mrim_pkt_init_header(pkt, 0, MRIM_CS_HELLO, 0);
    purple_circ_buffer_append(md->server.tx_buf, pkt, MRIM_PKT_TOTAL_LENGTH(pkt));
    g_free(pkt);
}

void
mrim_pkt_build_login(MrimData *md, gchar *login, gchar *pass,
                    guint32 status, gchar *agent)
{
    /* TODO here */    
}

void
mrim_pkt_build_ping(MrimData *md)
{
    MrimPktHeader *pkt = (MrimPktHeader*) g_malloc0(sizeof(MrimPktCsHello));
    mrim_pkt_init_header(pkt, 0, MRIM_CS_PING, 0);
    purple_circ_buffer_append(md->server.tx_buf, pkt, MRIM_PKT_TOTAL_LENGTH(pkt));
    g_free(pkt);
}

/* Server to Client messages */

static void
mrim_pkt_init_local(MrimPktLocal *loc, MrimPktHeader *pkt)
{
    loc->magic = GUINT32_FROM_BE(pkt->magic);
    loc->proto = GUINT32_FROM_BE(pkt->proto);
    loc->seq = GUINT32_FROM_BE(pkt->seq);
    loc->msg = GUINT32_FROM_BE(pkt->msg);
    loc->dlen = GUINT32_FROM_BE(pkt->dlen);
}

static MrimPktLocal *
mrim_pkt_to_local(MrimPktHeader *pkt)
{
    MrimPktLocal *loc = (MrimPktLocal*) g_malloc0();
}

/* Parses server packet in circle buffer, using rx_pkt_buf
 * as addtional linear temporary buffer.
 * Returns NULL if there is no sufficient data received to 
 * construct new packet
 */
MrimPktLocal *
mrim_pkt_parse(MrimData *md)
{
    guint max_read = 0;
    MrimPktHeader *pkt = NULL;

    /* copy complete packet header to the linear buffer */
    while (md->server.rx_pkt_buf->len < MRIM_PKT_HEADER_LENGTH) {
        max_read = purple_circ_buffer_get_max_read(md->server.rx_buf);
        if (!max_read) {
            return NULL; /* try again later */
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                max_read
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, max_read);
        }
    }
    pkt = (MrimPktHeader*) md->server.rx_pkt_buf->str;

    /* copy whole packet to the linear buffer */
    while (md->server.rx_pkt_buf->len < MRIM_PKT_TOTAL_LENGTH(pkt)) {
        max_read = purple_circ_buffer_get_max_read(md->server.rx_buf);
        if (!max_read) {
            return NULL; /* try again later */
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                max_read
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, max_read);
        }
    }
   
    /* ok, now we have complete packet. copy it and empty buffer */
    pkt = g_memdup(md->server.rx_pkt_buf->str, MRIM_PKT_TOTAL_LENGTH(pkt));
    g_string_truncate(md->server.rx_pkt_buf, 0);

    return pkt;
}


