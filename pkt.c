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
MrimPktHeader *
mrim_pkt_parse(MrimData *md)
{
    guint max_read = 0;
    /* TODO: parse algo */
    return NULL;
}
