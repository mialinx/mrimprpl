#include <purple.h>
#include "mrim.h"
#include "proto.h"

typedef struct
{
    guint32 length;
    gchar *data;
} MrimPktLps;

typedef mrim_packet_header_t MrimPktHeader;

#define MRIM_PKT_TOTAL_LENGTH(pkt) (pkt->dlen + sizeof(MrimPktHeader))
#define MRIM_PKT_HEADER_LENGTH (sizeof(MrimPktHeader))

/* Common routines */
void mrim_pkt_free(MrimPktHeader *pkt);

/* Client to Server messages */
typedef struct {
    MrimPktHeader header;
} MrimPktCsHello;

MrimPktHeader* mrim_pkt_cs_hello();

/* Server to Client messages */
typedef struct {
    MrimPktHeader header;
    guint32 timeout;
} MrimPktScHelloAck;

MrimPktHeader* mrim_pkt_parse(MrimData *md);
