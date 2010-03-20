#include "config.h"
#include <glib.h>
#include <purple.h>
#include <netinet/in.h>
#include <string.h>
#include "mrim.h"

/*
 * Returns the base icon name for the given buddy and account.
 * If buddy is NULL and the account is non-NULL, it will return the
 * name to use for the account's icon. If both are NULL, it will
 * return the name to use for the protocol's icon.
 *
 * This must be implemented.
 */
const char *
mrim_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
    return "mrim";
}

/*
 * Fills the four char**'s with string identifiers for "emblems"
 * that the UI will interpret and display as relevant
 */
const char *
mrim_list_emblem(PurpleBuddy *buddy)
{
    return "emblem";
}

/*
 * Gets a short string representing this buddy's status.  This will
 * be shown on the buddy list.
 */
char *
mrim_status_text(PurpleBuddy *buddy)
{
    return "status";
}

/*
 * Allows the prpl to add text to a buddy's tooltip.
 */
void 
mrim_tooltip_text (PurpleBuddy *buddy, PurpleNotifyUserInfo *nui, gboolean full)
{
}

/*
 * Returns a list of #PurpleStatusType which exist for this account;
 * this must be implemented, and must add at least the offline and
 * online states.
 */
GList *
mrim_status_types (PurpleAccount *account)
{
    PurpleStatusType *type = NULL;
    GList *list = NULL;

    type = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    type = purple_status_type_new_full(PURPLE_STATUS_AWAY, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    type = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    type = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    return list;
}

/*
 * Returns a list of #PurpleMenuAction structs, which represent extra
 * actions to be shown in (for example) the right-click menu for @a
 * node.
 */
GList *
mrim_blist_node_menu (PurpleBlistNode *node)
{
    return NULL;
}

/* Perform login */
static void
mrim_login_balancer_answered(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = (MrimData*) data;
    gchar buff[4 * 4 + 7]; //ipadd + port
    gint bytes = 0;

    // TODO from here
}

static void 
mrim_login_balancer_connected(gpointer data, gint source, const gchar *error_message) {
    MrimData *md = (MrimData*) data;

    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect to balancer %s", error_message);
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return;
    }

    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "balancer connected to %d\n", source);
    #endif
    
    md->balancer_fd = source;
    md->balancer_input_handler = purple_input_add(md->balancer_fd, PURPLE_INPUT_READ,
            mrim_login_balancer_answered, md);

    if (!md->balancer_input_handler) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Unable to connect to balancer"
        );
        return;
    }
}

void 
mrim_login(PurpleAccount *account)
{
    PurpleProxyConnectData *connect;
    MrimData *md;

    md = g_new0(MrimData, 1);
    md->account = account;
    md->balancer_port = (guint) purple_account_get_int(account, 
                "balancer_port", MRIMPRPL_BALANCER_DEFAULT_PORT);
    md->balancer_host = g_strdup(purple_account_get_string(account, 
                "balancer_host", MRIMPRPL_BALANCER_DEFAULT_HOST));
    
    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "resolving balancer host %s:%u", 
                md->balancer_host, md->balancer_port);
    #endif

    connect = purple_proxy_connect(NULL, md->account, md->balancer_host, md->balancer_port,
                mrim_login_balancer_connected, md);
    if (!connect) {
        purple_connection_error_reason(account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Unable to connect to balancer host"
        );
        return;
    }
}


/* Performs logout */
void 
mrim_close(PurpleConnection *gc)
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
int
mrim_send_im(PurpleConnection *gc, const char *who, const char *message, PurpleMessageFlags flags)
{
    return 0;
}

void 
mrim_set_info(PurpleConnection *gc, const char *info)
{
}

/*
 * @return If this protocol requires the PURPLE_TYPING message to
 *         be sent repeatedly to signify that the user is still
 *         typing, then the PRPL should return the number of
 *         seconds to wait before sending a subsequent notification.
 *         Otherwise the PRPL should return 0.
 */
unsigned int 
mrim_send_typing(PurpleConnection *gc, const char *name, PurpleTypingState state)
{
    return 0;
}

/**
 * Should arrange for purple_notify_userinfo() to be called with
 * who's user info.
 */
void 
mrim_get_info(PurpleConnection *gc, const char *who)
{
}

/* set account status */
void 
mrim_set_status(PurpleAccount *account, PurpleStatus *status)
{
}

/* set idle time */
void 
mrim_set_idle(PurpleConnection *gc, int idletime)
{
}

/* chage account passwd */
void 
mrim_change_passwd(PurpleConnection *gc, const char *old_pass, const char *new_pass)
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
void 
mrim_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{

}

/* Remove one buddy from a contact list */
void 
mrim_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
}

/* Will be called regularly for this prpl's
 * active connections.  You'd want to do this if you need to repeatedly
 * send some kind of keepalive packet to the server to avoid being
 * disconnected.  ("Regularly" is defined by
 * <code>KEEPALIVE_INTERVAL</code> in <tt>libpurple/connection.c</tt>.)
 */
void 
mrim_keepalive(PurpleConnection *gc)
{
}

/* Chane a buddy group on a server */
void 
mrim_group_buddy(PurpleConnection *gc, const char *who, const char *old_group, const char *new_group)
{
}

/* Rename group on a server side */
void 
mrim_rename_group(PurpleConnection *gc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
}

/*
 * Convert the username @a who to its canonical form.  (For example,
 * AIM treats "fOo BaR" and "foobar" as the same user; this function
 * should return the same normalized string for both of those.)
 */
const char *
mrim_normalize(const PurpleAccount *account, const char *who)
{
}

/* Removes group from a server */ 
void 
mrim_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
}

/* Checks whether offline messages to @a buddy are supported.
 * @return @c TRUE if @a buddy can be sent messages while they are
 *         offline, or @c FALSE if not.
 */
gboolean 
mrim_offline_message(const PurpleBuddy *buddy)
{
    return 1;
}

/* Sends buzzzzz signal to a buddy */
gboolean 
mrim_send_attention(PurpleConnection *gc, const char *username, guint type)
{
}

GList *
mrim_get_attention_types(PurpleAccount *account)
{
    return NULL;
}
