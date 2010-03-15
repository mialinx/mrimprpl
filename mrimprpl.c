#define PURPLE_PLUGINS

#include <glib.h>

#include "notify.h"
#include "plugin.h"
#include "prpl.h"
#include "version.h"

#define MRIMPRPL_ID "prpl-mialinx-mrim"
#define MRIMPRPL_NAME "Mail.Ru protocol"
#define MRIMPRPL_VERSION "1.0"
#define MRIMPRPL_AUTHOR "Dmitry Smal <mialinx@gmail.com>"
#define MRIMPRPL_WEBSITE ""
#define MRIMPRPL_SUMMARY "Mail.Ru agent protocol support plugin"
#define MRIMPRPL_DESCRIPTION MRIMPRPL_SUMMARY

/*================ INTARFACE ================*/

/*
 * Returns the base icon name for the given buddy and account.
 * If buddy is NULL and the account is non-NULL, it will return the
 * name to use for the account's icon. If both are NULL, it will
 * return the name to use for the protocol's icon.
 *
 * This must be implemented.
 */
static const char *
mrim_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
    return "mrim";
}

/*
 * Fills the four char**'s with string identifiers for "emblems"
 * that the UI will interpret and display as relevant
 */
static const char *
mrim_list_emblem(PurpleBuddy *b)
{
    return "emblem";
}

/*
 * Gets a short string representing this buddy's status.  This will
 * be shown on the buddy list.
 */
static const char *
mrim_status_text(PurpleBuddy *b)
{
    return "status";
}

/*
 * Allows the prpl to add text to a buddy's tooltip.
 */
static void 
mrim_tooltip_text (PurpleBuddy *b, PurpleNotifyUserInfo *nui, gboolean full)
{
}

/*
 * Returns a list of #PurpleStatusType which exist for this account;
 * this must be implemented, and must add at least the offline and
 * online states.
 */
static GList *
mrim_status_types (PurpleAccount *a)
{
    return NULL;
}

/*
 * Returns a list of #PurpleMenuAction structs, which represent extra
 * actions to be shown in (for example) the right-click menu for @a
 * node.
 */
static GList *
mrim_blist_node_menu (PurpleBlistNode *node)
{
    return NULL;
}

/* Perform login */
static void 
mrim_login(PurpleAccount *a)
{
    
}

/* Performs logout */
static void 
mrim_close(PurpleConnection *c)
{
}

/*
 * This PRPL function should return a positive value on success.
 * If the message is too big to be sent, return -E2BIG.  If
 * the account is not connected, return -ENOTCONN.  If the
 * PRPL is unable to send the message for another reason, return
 * some other negative value.  You can use one of the valid
 * errno values, or just big something.  If the message should
 * not be echoed to the conversation window, return 0.
 */
static int
mrim_send_im(PurpleConnection *c, const char *who, const char *message, PurpleMessageFlags flags)
{
    return 0;
}

static void 
mrim_set_info(PurpleConnection *c, const char *info)
{
}

/*
 * @return If this protocol requires the PURPLE_TYPING message to
 *         be sent repeatedly to signify that the user is still
 *         typing, then the PRPL should return the number of
 *         seconds to wait before sending a subsequent notification.
 *         Otherwise the PRPL should return 0.
 */
static unsigned int 
mrim_send_typing(PurpleConnection *c, const char *name, PurpleTypingState state)
{
    return 0;
}

/**
 * Should arrange for purple_notify_userinfo() to be called with
 * who's user info.
 */
static void 
mrim_get_info(PurpleConnection *c, const char *who)
{
}

/* set account status */
static void 
mrim_set_status(PurpleAccount *a, PurpleStatus *status)
{
}

/* set idle time */
static void 
mrim_set_idle(PurpleConnection *c, int idletime)
{
}

/* chage account passwd */
static void 
mrim_change_passwd(PurpleConnection *c, const char *old_pass, const char *new_pass)
{

}

/*
 * Add a buddy to a group on the server.
 *
 * This PRPL function may be called in situations in which the buddy is
 * already in the specified group. If the protocol supports
 * authorization and the user is not already authorized to see the
 * status of \a buddy, \a add_buddy should request authorization.
 */
static void 
mrim_add_buddy(PurpleConnection *c, PurpleBuddy *buddy, PurpleGroup *group)
{

}

/* Remove one buddy from a contact list */
static void 
mrim_remove_buddy(PurpleConnection *c, PurpleBuddy *buddy, PurpleGroup *group)
{
}

/* Will be called regularly for this prpl's
 * active connections.  You'd want to do this if you need to repeatedly
 * send some kind of keepalive packet to the server to avoid being
 * disconnected.  ("Regularly" is defined by
 * <code>KEEPALIVE_INTERVAL</code> in <tt>libpurple/connection.c</tt>.)
 */
static void 
mrim_keepalive(PurpleConnection *c)
{
}

/* Chane a buddy group on a server */
static void 
mrim_group_buddy(PurpleConnection *c, const char *who, const char *old_group, const char *new_group)
{
}

/* Rename group on a server side */
static void 
mrim_rename_group(PurpleConnection *c, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
}

/*
 * Convert the username @a who to its canonical form.  (For example,
 * AIM treats "fOo BaR" and "foobar" as the same user; this function
 * should return the same normalized string for both of those.)
 */
static const char 
mrim_normalize(const PurpleAccount *a, const char *who)
{
}

/* Removes group from a server */ 
static void 
mrim_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
}

/* Checks whether offline messages to @a buddy are supported.
 * @return @c TRUE if @a buddy can be sent messages while they are
 *         offline, or @c FALSE if not.
 */
static gboolean 
mrim_offline_message(const PurpleBuddy *buddy)
{
    return 1;
}

/* Sends buzzzzz signal to a buddy */
static gboolean 
mrim_send_attention(PurpleConnection *gc, const char *username, guint type)
{
}

static GList *
mrim_get_attention_types(PurpleAccount *acct)
{
    return NULL;
}
/*================ PLUGIN ================*/
static gboolean
plugin_load(PurplePlugin *plugin) 
{
    purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, "Hello World!",
                        "This is the Hello World! plugin :)", NULL, NULL, NULL);

    return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
    return TRUE;
}

void
plugin_destroy(PurplePlugin *plugin)
{
}

static PurplePluginProtocolInfo protocol_info = {
    0,                      /* Protocol options: no options for now */
    NULL,                   /* GList of PurpleAccountUserSplit (email, password). Filled in init */
    NULL,                   /* GList of PurpleAccountOption. Filled in init  */
    NO_BUDDY_ICONS,         /* PurpleBuddyIconSpec: no icons for now */
    mrim_list_icon,         /* (MUST) returns list icon name */
    mrim_list_emblem,       /* returns emblem test.. something like type of client.. not-authorized for eg */
    mrim_status_text,       /* returns a short string representing this buddy's status */
    mrim_tooltip_text,      /* allows the prpl to add text to a buddy's tooltip */
    mrim_status_types,      /* (MUST) returns a list of #PurpleStatusType which exist for this account */
    mrim_blist_node_menu,   /* returns a list of #PurpleMenuAction structs, which represent extra 
                               actions to be shown in (for example) the right-click menu for a node */
    NULL,                   /* chat support */
    NULL,                   /* chat support */
    /* All the server-related functions */
    mrim_login,             /* performs login */
    mrim_close,             /* performs logout */
    mrim_send_im,           /* sends istant message */
    mrim_set_info,          /* set's self user info */
    mrim_send_typing,       /* send 'typing..' notification */
    mrim_get_info,          /* retriev user info */
    mrim_set_status,        /* set status */
    mrim_set_idle,          /* set idle time */
    mrim_change_passwd,     /* change account passwd */
    mrim_add_buddy,         /* add one buddy to a contact list */
    NULL,                   /* void (*add_buddies)(PurpleConnection *, GList *buddies, GList *groups); */
    mrim_remove_buddy,      /* remove one buddy from a contact list */
    NULL,                   /* void (*remove_buddies)(PurpleConnection *, GList *buddies, GList *groups); */
    NULL,                   /* void (*add_permit)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*add_deny)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*rem_permit)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*rem_deny)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*set_permit_deny)(PurpleConnection *); */
    NULL,                   /* void (*join_chat)(PurpleConnection *, GHashTable *components); */
    NULL,                   /* void (*reject_chat)(PurpleConnection *, GHashTable *components); */
    NULL,                   /* char *(*get_chat_name)(GHashTable *components); */
    NULL,                   /* void (*chat_invite)(PurpleConnection *, int id, const char *message, const char *who); */
    NULL,                   /* void (*chat_leave)(PurpleConnection *, int id); */
    NULL,                   /* void (*chat_whisper)(PurpleConnection *, int id, const char *who, const char *message); */
    NULL,                   /* int  (*chat_send)(PurpleConnection *, int id, const char *message, PurpleMessageFlags flags); */
    mrim_keepalive,         /* send keepalive packet to server */
    NULL,                   /* void (*register_user)(PurpleAccount *); */
    NULL,                   /* deprecated: void (*get_cb_info)(PurpleConnection *, int, const char *who); */
    NULL,                   /* deprecated: void (*get_cb_away)(PurpleConnection *, int, const char *who); */
    NULL,                   /* void (*alias_buddy)(PurpleConnection *, const char *who, const char *alias); */
    mrim_group_buddy,       /* change a buddy's group on a server list/roster */
    mrim_rename_group,      /* rename a group on a server list/roster */
    NULL,                   /* void (*buddy_free)(PurpleBuddy *); */
    NULL,                   /* void (*convo_closed)(PurpleConnection *, const char *who); */
    mrim_normalize,         /* converts username to its canonical form */
    NULL,                   /* void (*set_buddy_icon)(PurpleConnection *, PurpleStoredImage *img); */
    mrim_remove_group,      /* removes group from a server */
    NULL,                   /* char *(*get_cb_real_name)(PurpleConnection *gc, int id, const char *who); */
    NULL,                   /* void (*set_chat_topic)(PurpleConnection *gc, int id, const char *topic); */
    NULL,                   /* PurpleChat *(*find_blist_chat)(PurpleAccount *account, const char *name); */
    
    /* room listing prpl callbacks */
    NULL,                   /* PurpleRoomlist *(*roomlist_get_list)(PurpleConnection *gc); */
    NULL,                   /* void (*roomlist_cancel)(PurpleRoomlist *list); */
    NULL,                   /* void (*roomlist_expand_category)(PurpleRoomlist *list, PurpleRoomlistRoom *category); */
  
    /* file transfer callbacks */
    NULL,                   /* gboolean (*can_receive_file)(PurpleConnection *, const char *who); */
    NULL,                   /* void (*send_file)(PurpleConnection *, const char *who, const char *filename); */
    NULL,                   /* PurpleXfer *(*new_xfer)(PurpleConnection *, const char *who); */
  
    /* misc */
    mrim_offline_message,   /* returns true if ofline messages are supported */
    NULL,                   /* PurpleWhiteboardPrplOps *whiteboard_prpl_ops; */
    NULL,                   /* int (*send_raw)(PurpleConnection *gc, const char *buf, int len); */
    NULL,                   /* char *(*roomlist_room_serialize)(PurpleRoomlistRoom *room); */
    NULL,                   /* void (*unregister_user)(PurpleAccount *, PurpleAccountUnregistrationCb cb, void *user_data); */
    mrim_send_attention,    /* send buzzzz signal to a buddy */
    mrim_get_attention_types, /* returns attention types */
    sizeof(protocol_info),
    NULL,
    NULL,
    NULL 
};

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,        /* libpurple magic */
    PURPLE_MAJOR_VERSION,       /* major version of libpurple */
    PURPLE_MINOR_VERSION,       /* minor version of libpurple */
    PURPLE_PLUGIN_STANDARD,     /* type of plugin */
    NULL,                       /* UI type of plugin. null for core plugins */
    0,                          /* plugin flags. no flags needed */
    NULL,                       /* GList of dependensies. flled in plugin_init */
    PURPLE_PRIORITY_DEFAULT,    /* priority of loading */

    MRIMPRPL_ID,                /* identifed of plugin */
    MRIMPRPL_NAME,              /* it's name */
    MRIMPRPL_VERSION,           /* and version */

    MRIMPRPL_SUMMARY,           /* summary */
    MRIMPRPL_DESCRIPTION,       /* description */
    MRIMPRPL_AUTHOR,            /* and author */
    MRIMPRPL_WEBSITE,           /* and yes, web site */

    plugin_load,                /* callback to load the plugin */
    plugin_unload,              /* callback for cleanup when unloaded */
    plugin_destroy,             /* callback for cleanup in case of emergency */

    NULL,                       /* pointer to UI specific part of info */
    &protocol_info,             /* pointer to protocol specific part of info */
    NULL,                       /* pointer to UI specific part for config frame */
    NULL,                       /* GList of plugin actions */
    NULL,                       /* here and the rest - for future use */
    NULL,
    NULL,
    NULL
};                               
    
static void                        
init_plugin(PurplePlugin *plugin)
{                                  
}

PURPLE_INIT_PLUGIN(hello_world, init_plugin, info)
