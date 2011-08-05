#ifndef PKT_H
#define PKT_H

#include <purple.h>
#include "mrim.h"
#include "proto.h"

typedef mrim_packet_header_t MrimPktHeader;
typedef gchar* Uidl;

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

void
mrim_pkt_build_message(MrimData *md, guint32 flags, const gchar *to, const gchar *message, 
                    const gchar *rtf_message);

void
mrim_pkt_build_message_recv(MrimData *md, gchar *from, guint32 msg_id);

void
mrim_pkt_build_offline_message_del(MrimData *md, Uidl uidl);

void
mrim_pkt_build_authorize(MrimData *md, const gchar *email);

void
mrim_pkt_build_wp_request(MrimData *md, guint32 count, ...);

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

typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
} MrimPktMessageAck;

/* chat */
typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    gchar *sender;
} MrimPktMultichatMessage;

typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    GList *members;
} MrimPktMultichatMembers;

typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    gchar *sender;
    GList *members;
} MrimPktMultichatAddMembers;

typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    GList *members;
} MrimPktMultichatAttached;

typedef struct {
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    GList *members;
} MrimPktMultichatDetached;

typedef struct { // not supported
    MrimPktHeader header;
    guint32 msg_id;
    guint32 flags;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
    gchar *multichat_name;
    gchar *sender;
} MrimPktMultichatInvite;

/* /chat */

typedef struct {
    MrimPktHeader header;
    Uidl uidl;
    guint32 flags;
    time_t time;
    gchar *from;
    gchar *message;
    gchar *rtf_message;
} MrimPktOfflineMessageAck;

typedef struct {
    MrimPktHeader header;
    guint32 status;
} MrimPktMessageStatus;

typedef struct {
    MrimPktHeader header;
    gchar *email;
} MrimPktAuthorizeAck;

typedef struct {
    MrimPktHeader header;
    guint32 status;
    guint32 field_num;
    guint32 max_rows;
    time_t server_time;
    GList *keys;
    GList *users;
} MrimPktAnketaInfo;

MrimPktHeader *
mrim_pkt_parse(MrimData *md);

#endif
