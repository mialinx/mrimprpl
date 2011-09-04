#ifndef MRIM_H
#define MRIM_H

#include "config.h"
#include <glib.h>
#include <purple.h>
#include "proto.h"

#define MRIMPRPL_BALANCER_DEFAULT_PORT 2042
#define MRIMPRPL_BALANCER_DEFAULT_HOST "mrim.mail.ru"

typedef struct {
    guint32 id;
    guint32 flags;
    gchar *nick;
} MrimGroup;

typedef struct {
    guint32 id;
    guint32 flags;
    guint32 server_flags;
    guint32 status;
    guint32 group_id;
    gchar *email;
    gchar *nick;
} MrimContact;

MrimGroup*
mrim_group_new(const guint32 id, const guint32 flags, const gchar *nick);

MrimContact*
mrim_contact_new(const guint32 id, const guint32 flags, const guint32 server_flags, 
            const guint32 status, const guint32 group_id, const gchar *email, const gchar *nick);

typedef struct {

    PurpleAccount *account;
    
    struct {
        char *host;
        guint port;
        PurpleProxyConnectData *connect_data;
        gint fd;
        guint read_handle;
    } balancer;

    struct {
        char *host;
        guint port;
        PurpleProxyConnectData *connect_data;
        gint fd;
        guint read_handle;
        guint write_handle;
        PurpleCircBuffer *rx_buf;
        GString *rx_pkt_buf;
        PurpleCircBuffer *tx_buf;
    } server;

    guint32 keepalive; 
    guint32 keepalive_handle;
    guint32 tx_seq;

    GHashTable *groups;
    GHashTable *contacts;
    GHashTable *attempts;
} MrimData;

const char *
mrim_list_icon(PurpleAccount *account, PurpleBuddy *buddy);

const char *
mrim_list_emblem(PurpleBuddy *buddy);

char *
mrim_status_text(PurpleBuddy *buddy);

void
mrim_tooltip_text (PurpleBuddy *buddy, PurpleNotifyUserInfo *nui, gboolean full);

GList *
mrim_status_types (PurpleAccount *account);

GList *
mrim_blist_node_menu (PurpleBlistNode *node);

GList*
mrim_chat_info(PurpleConnection *gc);

void
mrim_login(PurpleAccount *account);

void
mrim_close(PurpleConnection *gc);

int
mrim_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags);

void
mrim_set_info(PurpleConnection *gc, const char *info);

unsigned int
mrim_send_typing(PurpleConnection *gc, const char *email, PurpleTypingState state);

void
mrim_get_info(PurpleConnection *gc, const char *who);

void
mrim_set_status(PurpleAccount *account, PurpleStatus *status);

void
mrim_set_idle(PurpleConnection *gc, int idletime);

void
mrim_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);

void
mrim_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group);

void
mrim_join_chat(PurpleConnection *gc, GHashTable *components);

void 
mrim_chat_leave(PurpleConnection *gc, gint id);

void 
mrim_chat_reject(PurpleConnection *gc, GHashTable *components);

void 
mrim_chat_invite(PurpleConnection *gc, gint id, const gchar *message, const gchar *who);

int 
mrim_chat_send(PurpleConnection *gc, gint id, const gchar *message, PurpleMessageFlags flags);

void 
mrim_alias_buddy(PurpleConnection *gc, const char *who, const char *alias);

void
mrim_group_buddy(PurpleConnection *gc, const char *who, const char *old_group, const char *new_group);

void
mrim_rename_group(PurpleConnection *gc, const char *old_nick, PurpleGroup *group, GList *moved_buddies);

const char *
mrim_normalize(const PurpleAccount *account, const char *who);

void
mrim_remove_group(PurpleConnection *gc, PurpleGroup *group);

PurpleChat*
mrim_find_blist_chat(PurpleAccount *account, const char *name);

gboolean
mrim_offline_message(const PurpleBuddy *buddy);

#endif /*MRIM_H*/
