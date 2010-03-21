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
mrim_pkt_init_header(MrimPacketHeader *header, guint32 seq, guint32 msg, guint32 dlen) 
{
    if (header) {
        header->magic = CS_MAGIC;
        header->proto = PROTO_VERSION;
        header->seq = seq;
        header->msg = msg;
        header->dlen = dlen;
    }
}

/* Client to Server messages */

MrimPktCsHello *
mrim_pkt_cs_hello() {
    MrimPktCsHello *pkt = g_new0(MrimPktCsHello, 1);
    mrim_pkt_init_header(pkt, 0, MRIM_CS_HELLO, 0);
    return pkt;
}
