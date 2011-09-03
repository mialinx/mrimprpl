#include <glib.h>
#include <purple.h>

#include "mrim.h"

#define MRIMPRPL_ID "prpl-mialinx-mrim"
#define MRIMPRPL_NAME "Mail.Ru Agent"
#define MRIMPRPL_VERSION "0.1"
#define MRIMPRPL_AUTHOR "Dmitry Smal <mialinx@gmail.com>"
#define MRIMPRPL_WEBSITE ""
#define MRIMPRPL_SUMMARY "Mail.Ru agent protocol support plugin"
#define MRIMPRPL_DESCRIPTION MRIMPRPL_SUMMARY

static PurplePluginProtocolInfo protocol_info = {
    0,                      /* Protocol options: no options for now */
    NULL,                   /* GList of PurpleAccountUserSplit (email, password). Filled in init */
    NULL,                   /* GList of PurpleAccountOption. Filled in init  */
    NO_BUDDY_ICONS,         /* PurpleBuddyIconSpec: no icons for now */
    mrim_list_icon,         /* (MUST) returns list icon name */
    mrim_list_emblem,       /* returns emblem test.. something like type of client.. not-authorized for eg */
    NULL,                   /* returns a short string representing this buddy's status */
    mrim_tooltip_text,      /* allows the prpl to add text to a buddy's tooltip */
    mrim_status_types,      /* (MUST) returns a list of #PurpleStatusType which exist for this account */
    mrim_blist_node_menu,   /* returns a list of #PurpleMenuAction structs, which represent extra 
                               actions to be shown in (for example) the right-click menu for a node */
    mrim_chat_info,         /* returns list of options, needed to join the chat */
    NULL,                   /* returns hash table with options defaults */
    /* All the server-related functions */
    mrim_login,             /* performs login */
    mrim_close,             /* performs logout */
    mrim_send_im,           /* sends istant message */
    NULL,                   /* set's self user info */
    mrim_send_typing,       /* send 'typing..' notification */
    mrim_get_info,          /* retriev user info */
    mrim_set_status,        /* set status */
    mrim_set_idle,          /* set idle time */
    NULL,                   /* change account passwd */
    mrim_add_buddy,         /* add one buddy to a contact list */
    NULL,                   /* void (*add_buddies)(PurpleConnection *, GList *buddies, GList *groups); */
    mrim_remove_buddy,      /* remove one buddy from a contact list */
    NULL,                   /* void (*remove_buddies)(PurpleConnection *, GList *buddies, GList *groups); */
    NULL,                   /* void (*add_permit)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*add_deny)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*rem_permit)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*rem_deny)(PurpleConnection *, const char *name); */
    NULL,                   /* void (*set_permit_deny)(PurpleConnection *); */
    mrim_join_chat,         /* void (*join_chat)(PurpleConnection *, GHashTable *components); */
    NULL,                   /* void (*reject_chat)(PurpleConnection *, GHashTable *components); */
    NULL,                   /* char *(*get_chat_name)(GHashTable *components); */
    NULL,                   /* void (*chat_invite)(PurpleConnection *, int id, const char *message, const char *who); */
    mrim_chat_leave,        /* void (*chat_leave)(PurpleConnection *, int id); */
    NULL,                   /* void (*chat_whisper)(PurpleConnection *, int id, const char *who, const char *message); */
    NULL,                   /* int  (*chat_send)(PurpleConnection *, int id, const char *message, PurpleMessageFlags flags); */
    NULL,                   /* send keepalive packet to server */
    NULL,                   /* void (*register_user)(PurpleAccount *); */
    NULL,                   /* deprecated: void (*get_cb_info)(PurpleConnection *, int, const char *who); */
    NULL,                   /* deprecated: void (*get_cb_away)(PurpleConnection *, int, const char *who); */
    mrim_alias_buddy,       /* void (*alias_buddy)(PurpleConnection *, const char *who, const char *alias); */
    mrim_group_buddy,       /* change a buddy's group on a server list/roster */
    mrim_rename_group,      /* rename a group on a server list/roster */
    NULL,                   /* void (*buddy_free)(PurpleBuddy *); */
    NULL,                   /* void (*convo_closed)(PurpleConnection *, const char *who); */
    mrim_normalize,         /* converts username to its canonical form */
    NULL,                   /* void (*set_buddy_icon)(PurpleConnection *, PurpleStoredImage *img); */
    mrim_remove_group,      /* removes group from a server */
    NULL,                   /* char *(*get_cb_real_name)(PurpleConnection *gc, int id, const char *who); */
    NULL,                   /* void (*set_chat_topic)(PurpleConnection *gc, int id, const char *topic); */
    mrim_find_blist_chat,   /* PurpleChat *(*find_blist_chat)(PurpleAccount *account, const char *name); */
    
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
    NULL,                   /* send buzzzz signal to a buddy */
    NULL,                   /* returns attention types */
    sizeof(protocol_info),
    NULL,
    NULL,
    NULL 
};

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,        /* libpurple magic */
    PURPLE_MAJOR_VERSION,       /* major version of libpurple */
    PURPLE_MINOR_VERSION,       /* minor version of libpurple */
    PURPLE_PLUGIN_PROTOCOL,     /* type of plugin */
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

    NULL,                       /* callback to load the plugin */
    NULL,                       /* callback for cleanup when unloaded */
    NULL,                       /* callback for cleanup in case of emergency */

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
    PurpleAccountOption *option;
    PurpleAccountUserSplit *split;

    option = purple_account_option_string_new("Balancer host", "balancer_host", MRIMPRPL_BALANCER_DEFAULT_HOST);
    protocol_info.protocol_options = g_list_append(protocol_info.protocol_options, option);

    option = purple_account_option_int_new("Balancer port", "balancer_port", MRIMPRPL_BALANCER_DEFAULT_PORT);
    protocol_info.protocol_options = g_list_append(protocol_info.protocol_options, option);

    /*
    option = purple_account_option_bool_new("Notify about Emails", "notify_emails", FALSE);
    protocol_info.protocol_options = g_list_append(protocol_info.protocol_options, option);
    */
}

PURPLE_INIT_PLUGIN(mrimprpl, init_plugin, info)
