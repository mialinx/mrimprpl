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

static const char *
mrim_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
    return "mrim";
}

static const char *
mrim_list_emblem(PurpleBuddy *b)
{
    return "emblem";
}

static const char *
mrim_status_text(PurpleBuddy *b)
{
    return "status";
}

void 
mrim_tooltip_text (PurpleBuddy *b, PurpleNotifyUserInfo *nui, gboolean full)
{
}

GList *
mrim_status_types (PurpleAccount *a)
{
    return NULL;
}

GList *
mrim_blist_node_menu (PurpleBlistNode *node)
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

//   /**
//    * Returns a list of #proto_chat_entry structs, which represent
//    * information required by the PRPL to join a chat. libpurple will
//    * call join_chat along with the information filled by the user.
//    *
//    * @return A list of #proto_chat_entry structs
//    */
//   GList *(*chat_info)(PurpleConnection *);
//
//   /**
//    * Returns a hashtable which maps #proto_chat_entry struct identifiers
//    * to default options as strings based on chat_name. The resulting 
//    * hashtable should be created with g_hash_table_new_full(g_str_hash,
//    * g_str_equal, NULL, g_free);. Use #get_chat_name if you instead need
//    * to extract a chat name from a hashtable.
//    *
//    * @param chat_name The chat name to be turned into components
//    * @return Hashtable containing the information extracted from chat_name
//    */
//   GHashTable *(*chat_info_defaults)(PurpleConnection *, const char *chat_name);
//
//   /* All the server-related functions */
//
//   /** This must be implemented. */
//   void (*login)(PurpleAccount *);
//
//   /** This must be implemented. */
//   void (*close)(PurpleConnection *);
//
//   /**
//    * This PRPL function should return a positive value on success.
//    * If the message is too big to be sent, return -E2BIG.  If
//    * the account is not connected, return -ENOTCONN.  If the
//    * PRPL is unable to send the message for another reason, return
//    * some other negative value.  You can use one of the valid
//    * errno values, or just big something.  If the message should
//    * not be echoed to the conversation window, return 0.
//    */
//   int  (*send_im)(PurpleConnection *, const char *who,
//                   const char *message,
//                   PurpleMessageFlags flags);
//
//   void (*set_info)(PurpleConnection *, const char *info);
//
//   /**
//    * @return If this protocol requires the PURPLE_TYPING message to
//    *         be sent repeatedly to signify that the user is still
//    *         typing, then the PRPL should return the number of
//    *         seconds to wait before sending a subsequent notification.
//    *         Otherwise the PRPL should return 0.
//    */
//   unsigned int (*send_typing)(PurpleConnection *, const char *name, PurpleTypingState state);
//
//   /**
//    * Should arrange for purple_notify_userinfo() to be called with
//    * @a who's user info.
//    */
//   void (*get_info)(PurpleConnection *, const char *who);
//   void (*set_status)(PurpleAccount *account, PurpleStatus *status);
//
//   void (*set_idle)(PurpleConnection *, int idletime);
//   void (*change_passwd)(PurpleConnection *, const char *old_pass,
//                         const char *new_pass);
//   /**
//    * Add a buddy to a group on the server.
//    *
//    * This PRPL function may be called in situations in which the buddy is
//    * already in the specified group. If the protocol supports
//    * authorization and the user is not already authorized to see the
//    * status of \a buddy, \a add_buddy should request authorization.
//    */
//   void (*add_buddy)(PurpleConnection *, PurpleBuddy *buddy, PurpleGroup *group);
//   void (*add_buddies)(PurpleConnection *, GList *buddies, GList *groups);
//   void (*remove_buddy)(PurpleConnection *, PurpleBuddy *buddy, PurpleGroup *group);
//   void (*remove_buddies)(PurpleConnection *, GList *buddies, GList *groups);
//   void (*add_permit)(PurpleConnection *, const char *name);
//   void (*add_deny)(PurpleConnection *, const char *name);
//   void (*rem_permit)(PurpleConnection *, const char *name);
//   void (*rem_deny)(PurpleConnection *, const char *name);
//   void (*set_permit_deny)(PurpleConnection *);
//
//   /**
//    * Called when the user requests joining a chat. Should arrange for
//    * #serv_got_joined_chat to be called.
//    *
//    * @param components A hashtable containing information required to
//    *                   join the chat as described by the entries returned
//    *                   by #chat_info. It may also be called when accepting
//    *                   an invitation, in which case this matches the
//    *                   data parameter passed to #serv_got_chat_invite.
//    */
//   void (*join_chat)(PurpleConnection *, GHashTable *components);
//
//   /**
//    * Called when the user refuses a chat invitation.
//    *
//    * @param components A hashtable containing information required to
//    *                   join the chat as passed to #serv_got_chat_invite.
//    */
//   void (*reject_chat)(PurpleConnection *, GHashTable *components);
//
//   /**
//    * Returns a chat name based on the information in components. Use
//    * #chat_info_defaults if you instead need to generate a hashtable 
//    * from a chat name.
//    *
//    * @param components A hashtable containing information about the chat.
//    */
//   char *(*get_chat_name)(GHashTable *components);
//
//   /**
//    * Invite a user to join a chat.
//    *
//    * @param id      The id of the chat to invite the user to.
//    * @param message A message displayed to the user when the invitation 
//    *                is received.
//    * @param who     The name of the user to send the invation to.
//    */
//   void (*chat_invite)(PurpleConnection *, int id,
//                       const char *message, const char *who);
//   /**
//    * Called when the user requests leaving a chat.
//    *
//    * @param id The id of the chat to leave
//    */
//   void (*chat_leave)(PurpleConnection *, int id);
//
//   /**
//    * Send a whisper to a user in a chat.
//    *
//    * @param id      The id of the chat.
//    * @param who     The name of the user to send the whisper to.
//    * @param message The message of the whisper.
//    */
//   void (*chat_whisper)(PurpleConnection *, int id,
//                        const char *who, const char *message);
//
//   /**
//    * Send a message to a chat.
//    * This PRPL function should return a positive value on success.
//    * If the message is too big to be sent, return -E2BIG.  If
//    * the account is not connected, return -ENOTCONN.  If the
//    * PRPL is unable to send the message for another reason, return
//    * some other negative value.  You can use one of the valid
//    * errno values, or just big something.  If the message should
//    * not be echoed to the conversation window, return 0.
//    *
//    * @param id      The id of the chat to send the message to.
//    * @param message The message to send to the chat.
//    * @param flags   A bitwise OR of #PurpleMessageFlags representing
//    *                message flags.
//    * @return    A positive number or 0 in case of succes,
//    *                a negative error number in case of failure.
//    */
//   int  (*chat_send)(PurpleConnection *, int id, const char *message, PurpleMessageFlags flags);
//
//   /** If implemented, this will be called regularly for this prpl's
//    *  active connections.  You'd want to do this if you need to repeatedly
//    *  send some kind of keepalive packet to the server to avoid being
//    *  disconnected.  ("Regularly" is defined by
//    *  <code>KEEPALIVE_INTERVAL</code> in <tt>libpurple/connection.c</tt>.)
//    */
//   void (*keepalive)(PurpleConnection *);
//
//   /** new user registration */
//   void (*register_user)(PurpleAccount *);
//
//   /**
//    * @deprecated Use #PurplePluginProtocolInfo.get_info instead.
//    */
//   void (*get_cb_info)(PurpleConnection *, int, const char *who);
//   /**
//    * @deprecated Use #PurplePluginProtocolInfo.get_cb_real_name and
//    *             #PurplePluginProtocolInfo.status_text instead.
//    */
//   void (*get_cb_away)(PurpleConnection *, int, const char *who);
//
//   /** save/store buddy's alias on server list/roster */
//   void (*alias_buddy)(PurpleConnection *, const char *who,
//                       const char *alias);
//
//   /** change a buddy's group on a server list/roster */
//   void (*group_buddy)(PurpleConnection *, const char *who,
//                       const char *old_group, const char *new_group);
//
//   /** rename a group on a server list/roster */
//   void (*rename_group)(PurpleConnection *, const char *old_name,
//                        PurpleGroup *group, GList *moved_buddies);
//
//   void (*buddy_free)(PurpleBuddy *);
//
//   void (*convo_closed)(PurpleConnection *, const char *who);
//
//   /**
//    *  Convert the username @a who to its canonical form.  (For example,
//    *  AIM treats "fOo BaR" and "foobar" as the same user; this function
//    *  should return the same normalized string for both of those.)
//    */
//   const char *(*normalize)(const PurpleAccount *, const char *who);
//
//   /**
//    * Set the buddy icon for the given connection to @a img.  The prpl
//    * does NOT own a reference to @a img; if it needs one, it must
//    * #purple_imgstore_ref(@a img) itself.
//    */
//   void (*set_buddy_icon)(PurpleConnection *, PurpleStoredImage *img);
//
//   void (*remove_group)(PurpleConnection *gc, PurpleGroup *group);
//
//   /** Gets the real name of a participant in a chat.  For example, on
//    *  XMPP this turns a chat room nick <tt>foo</tt> into
//    *  <tt>room\@server/foo</tt>
//    *  @param gc  the connection on which the room is.
//    *  @param id  the ID of the chat room.
//    *  @param who the nickname of the chat participant.
//    *  @return    the real name of the participant.  This string must be
//    *             freed by the caller.
//    */
//   char *(*get_cb_real_name)(PurpleConnection *gc, int id, const char *who);
//
//   void (*set_chat_topic)(PurpleConnection *gc, int id, const char *topic);
//
//   PurpleChat *(*find_blist_chat)(PurpleAccount *account, const char *name);
//
//   /* room listing prpl callbacks */
//   PurpleRoomlist *(*roomlist_get_list)(PurpleConnection *gc);
//   void (*roomlist_cancel)(PurpleRoomlist *list);
//   void (*roomlist_expand_category)(PurpleRoomlist *list, PurpleRoomlistRoom *category);
//
//   /* file transfer callbacks */
//   gboolean (*can_receive_file)(PurpleConnection *, const char *who);
//   void (*send_file)(PurpleConnection *, const char *who, const char *filename);
//   PurpleXfer *(*new_xfer)(PurpleConnection *, const char *who);
//
//   /** Checks whether offline messages to @a buddy are supported.
//    *  @return @c TRUE if @a buddy can be sent messages while they are
//    *          offline, or @c FALSE if not.
//    */
//   gboolean (*offline_message)(const PurpleBuddy *buddy);
//
//   PurpleWhiteboardPrplOps *whiteboard_prpl_ops;
//
//   /** For use in plugins that may understand the underlying protocol */
//   int (*send_raw)(PurpleConnection *gc, const char *buf, int len);
//
//   /* room list serialize */
//   char *(*roomlist_room_serialize)(PurpleRoomlistRoom *room);
//
//   /** Remove the user from the server.  The account can either be
//    * connected or disconnected. After the removal is finished, the
//    * connection will stay open and has to be closed!
//    */
//   /* This is here rather than next to register_user for API compatibility
//    * reasons.
//    */
//   void (*unregister_user)(PurpleAccount *, PurpleAccountUnregistrationCb cb, void *user_data);
//
//   /* Attention API for sending & receiving zaps/nudges/buzzes etc. */
//   gboolean (*send_attention)(PurpleConnection *gc, const char *username, guint type);
//   GList *(*get_attention_types)(PurpleAccount *acct);
//
//   /**
//    * The size of the PurplePluginProtocolInfo. This should always be sizeof(PurplePluginProtocolInfo).
//    * This allows adding more functions to this struct without requiring a major version bump.
//    */
//   unsigned long struct_size;
//
//   /* NOTE:
//    * If more functions are added, they should accessed using the following syntax:
//    *
//    *      if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl, new_function))
//    *          prpl->new_function(...);
//    *
//    * instead of
//    *
//    *      if (prpl->new_function != NULL)
//    *          prpl->new_function(...);
//    *
//    * The PURPLE_PROTOCOL_PLUGIN_HAS_FUNC macro can be used for the older member
//    * functions (e.g. login, send_im etc.) too.
//    */
//
//   /** This allows protocols to specify additional strings to be used for
//    * various purposes.  The idea is to stuff a bunch of strings in this hash
//    * table instead of expanding the struct for every addition.  This hash
//    * table is allocated every call and MUST be unrefed by the caller.
//    *
//    * @param account The account to specify.  This can be NULL.
//    * @return The protocol's string hash table. The hash table should be
//    *         destroyed by the caller when it's no longer needed.
//    */
//   GHashTable *(*get_account_text_table)(PurpleAccount *account);
//
//   /**
//    * Initiate a media session with the given contact.
//    *
//    * @param account The account to initiate the media session on.
//    * @param who The remote user to initiate the session with.
//    * @param type The type of media session to initiate.
//    * @return TRUE if the call succeeded else FALSE. (Doesn't imply the media session or stream will be successfully created)
//    */
//   gboolean (*initiate_media)(PurpleAccount *account, const char *who,
//                   PurpleMediaSessionType type);
//
//   /**
//    * Checks to see if the given contact supports the given type of media session.
//    *
//    * @param account The account the contact is on.
//    * @param who The remote user to check for media capability with.
//    * @return The media caps the contact supports.
//    */
//   PurpleMediaCaps (*get_media_caps)(PurpleAccount *account,
//                     const char *who);
//
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
