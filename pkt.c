#include <glib.h>
#include <string.h>
#include "pkt.h"

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

static void
mrim_pkt_init_header(MrimPktHeader *header, guint32 seq, guint32 msg, guint32 dlen) 
{
    if (header) {
        header->magic = CS_MAGIC;
        header->proto = PROTO_VERSION;
        header->seq = seq;
        header->msg = msg;
        header->dlen = dlen;
    }
}

/* Common routines */
void
mrim_pkt_free(MrimPktHeader *pkt) 
{
    if (pkt) {
        switch (pkt->msg) {
            case MRIM_CS_HELLO:
                g_free(pkt);
                break;
            case MRIM_CS_HELLO_ACK:
                g_free(pkt);
                break;
            default:
                #ifdef ENABLE_MRIM_DEBUG
                purple_debug_info("mrim", "unsupported type of packet %u\n", 
                    (guint) pkt->msg);
                #endif
                break;
        }
    }
}

/* Client to Server messages */
MrimPktHeader *
mrim_pkt_cs_hello() 
{
    MrimPktHeader *pkt = NULL;

    pkt = (MrimPktHeader*) g_malloc0(sizeof(MrimPktCsHello));
    mrim_pkt_init_header(pkt, 0, MRIM_CS_HELLO, 0);
    return pkt;
}

/* Server to Client messages */

/* Parses server packet in circle buffer, using rx_pkt_buf
 * as addtional linear temporary buffer.
 * Returns NULL if there is no sufficient data received to 
 * construct new packet
 */
MrimPktHeader *
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
