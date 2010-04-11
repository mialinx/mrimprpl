#ifndef PKT_H
#define PKT_H

#include <purple.h>
#include "mrim.h"
#include "proto.h"

typedef mrim_packet_header_t MrimPktHeader;

/* Common routines */
void
mrim_pkt_free(MrimPktHeader *pkt);

/* Client to Server messages */
void
mrim_pkt_build_hello(MrimData *md);

void
mrim_pkt_build_login(MrimData *md, const gchar *login, const gchar *pass,
                    guint32 status, const gchar *agent);

void
mrim_pkt_build_ping(MrimData *md);

void
mrim_pkt_build_change_status(MrimData *md, guint32 status);

void
mrim_pkt_build_add_contact(MrimData *md, guint32 flags, guint32 group_id, 
                    const gchar *email, const gchar *name);
                    
void
mrim_pkt_build_modify_contact(MrimData *md, guint32 id, guint32 flags, guint32 group_id, 
                    const gchar *email, const gchar *name);
/* Server to Client messages */
typedef struct {
    MrimPktHeader header;
    guint32 timeout;
} MrimPktHelloAck;

typedef struct {
    MrimPktHeader header;
} MrimPktLoginAck;

typedef struct {
    MrimPktHeader header;
    gchar *reason;
} MrimPktLoginRej;

typedef struct {
    MrimPktHeader header;
    GHashTable *info;
} MrimPktUserInfo;

typedef struct {
    MrimPktHeader header;
    guint32 timeout;
} MrimPktConnectionParams;

typedef struct {
    MrimPktHeader header;
    guint32 reason;
} MrimPktLogout;

typedef struct {
    MrimPktHeader header;
    guint32 status;
    GList *groups;
    GList *contacts;
} MrimPktContactList;

typedef struct {
    guint32 flags;
    gchar *name;
} MrimGroup;

typedef struct {
    guint32 flags;
    guint32 group_id;
    gchar *email;
    gchar *nick;
    guint32 server_flags;
    guint32 status;
} MrimContact;

typedef struct {
    MrimPktHeader header;
    guint32 status;
    gchar *email;
} MrimPktUserStatus;

typedef struct {
    MrimPktHeader header;
    guint32 status;
    guint32 contact_id;
} MrimPktAddContactAck;

typedef struct {
    MrimPktHeader header;
    guint32 status;
} MrimPktModifyContactAck;

MrimPktHeader *
mrim_pkt_parse(MrimData *md);

#endif
