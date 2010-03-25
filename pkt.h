#include <purple.h>
#include "mrim.h"
#include "proto.h"

#define MRIM_PKT_TOTAL_LENGTH(pkt) (pkt->dlen + sizeof(MrimPktHeader))
#define MRIM_PKT_HEADER_LENGTH (sizeof(MrimPktHeader))

typedef struct {
    guint32 length;
    gchar *data;
} MrimPktLps;

typedef mrim_packet_header_t MrimPktHeader;

typedef mrim_packet_header_t MrimPktLocal;

/* Common routines */
void
mrim_pkt_free(MrimPktLocal *pkt);

/* Client to Server messages */
void
mrim_pkt_build_hello(MrimData *md);

void
mrim_pkt_build_login(MrimData *md, gchar *login, gchar *pass,
                    guint32 status, gchar *agent);

void
mrim_pkt_build_ping(MrimData *md);

/* Server to Client messages */
typedef struct {
    MrimPktLocal header;
    guint32 timeout;
} MrimPktHelloAck;

typedef struct {
    MrimPktLocal header;
} MrimPktLoginAck;

typedef struct {
    MrimPktLocal header;
    gchar *reason;
} MrimPktLoginRej;

MrimPktLocal *
mrim_pkt_parse(MrimData *md);
