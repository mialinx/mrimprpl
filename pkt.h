#include <purple.h>
#include "proto.h"

typedef struct
{
    guint32 length;
    gchar *data;
} MrimPktLps;

typedef mrim_packet_header_t MrimPacketHeader;

#define MRIM_PKT_TOTAL_LENGTH(pkt) (pkt->dlen + sizeof(MrimPacketHeader))

/* Client to Server messages */
typedef struct {
    MrimPacketHeader header;
} MrimPktCsHello;

MrimPktCsHello* mrim_pkt_cs_hello();

/* Server to Client messages */
typedef struct {
    MrimPacketHeader header;
    guint32 timeout;
} MrimPktScHelloAck;

MrimPacketHeader* mrim_pkt_parse(PurpleCircBuffer *buf);
