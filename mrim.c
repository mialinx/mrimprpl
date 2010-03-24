#include "config.h"
#include <glib.h>
#include <purple.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "mrim.h"
#include "pkt.h"

#define MRIM_CIRC_BUFFER_GROW (16 * 1024)
#define MRIM_LINR_BUFFER_INIT (1024)

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

/* Basic read/write ops */

static void
mrim_server_canwrite_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = (MrimData*) data;
    guint max_read = 0;
    gint bytes_written = 0;

fprintf(stderr, "server_canwrite_cb\n");

    while (max_read = purple_circ_buffer_get_max_read(md->server.tx_buf)) {
        bytes_written = write(source, md->server.tx_buf->outptr, max_read);
        if (bytes_written > 0) {
            purple_circ_buffer_mark_read(md->server.tx_buf, bytes_written);
        }
        else {
            purple_connection_error_reason(md->account->gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Server connection was lost"
            );
        }
    }

    purple_input_remove(md->server.write_ih);
}

static gboolean
mrim_server_send_pkt(MrimData *md, MrimPktHeader *pkt)
{
    if (!pkt) {
        return FALSE;
    }

    purple_circ_buffer_append(md->server.tx_buf, pkt, MRIM_PKT_TOTAL_LENGTH(pkt));
    if (!md->server.write_ih) {
        md->server.write_ih = purple_input_add(md->server.fd, PURPLE_INPUT_WRITE,
            mrim_server_canwrite_cb, md);
        if (!md->server.write_ih) {
            purple_connection_error_reason(md->account->gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Failed to connect to server"
            );
            return FALSE;
        }
    }

    return TRUE;
}

static void
mrim_server_dispatch_pkt(MrimData *md, MrimPktHeader *pkt)
{
fprintf(stderr, "dispatching message: %x\n", pkt->msg);
}

static void
mrim_server_canread_cb(gpointer data, gint source, PurpleInputCondition cond)
{

    MrimData *md = (MrimData*) data;
    gint bytes_read = 0;
    #define MRIM_ITERM_BUFF_LEN (4 * 1024)
    gchar buff[MRIM_ITERM_BUFF_LEN];
    MrimPktHeader *pkt = NULL;

fprintf(stderr, "server_canread_cb\n");

    while ((bytes_read = read(source, buff, MRIM_ITERM_BUFF_LEN)) > 0) {
        purple_circ_buffer_append(md->server.rx_buf, buff, bytes_read);
    }
    if (bytes_read == 0 || (bytes_read < 0 && errno != EWOULDBLOCK)) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Server connection was lost"
        );
        purple_input_remove(md->server.read_ih);
    }
    else {
        if (pkt = mrim_pkt_parse(md)) {
            mrim_server_dispatch_pkt(md, pkt);
            mrim_pkt_free(pkt);
        }
    }
}


/* Perform login */
static void
mrim_login_server_connected(gpointer data, gint source, const gchar *error_message)
{
    MrimData *md = (MrimData*) data;
    MrimPktHeader *pkt = NULL;

    md->server.connect_data = NULL;
    if (source < 0) {
        gchar *tmp = g_strdup_printf("Failed to connect to server: %s\n", error_message);
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp
        );
        g_free(tmp);
        return;
    }

    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "server connected fd = %d\n", source);
    #endif

    md->server.fd = source;
    md->server.read_ih = purple_input_add(md->server.fd, PURPLE_INPUT_READ,
        mrim_server_canread_cb, md);
    if (!md->server.read_ih) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to connect to server"
        );
        return;
    }

    pkt = mrim_pkt_cs_hello();
    mrim_server_send_pkt(md, pkt);
    mrim_pkt_free(pkt);
}

static void
mrim_login_balancer_answered(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = (MrimData*) data;
    guint buff_size = 32;
    gchar *buff; /*ipadd + port*/
    gchar **buff_split;

    buff = g_malloc0(buff_size);
    read(source, buff, buff_size);
    g_strchomp(buff);
    buff_split = g_strsplit(buff, ":", 2);
    md->server.host = g_strdup(buff_split[0]);
    md->server.port = (guint) atoi(buff_split[1]);
    g_strfreev(buff_split);
    g_free(buff);
    purple_input_remove(md->balancer.read_ih);
    md->balancer.read_ih = 0;

    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "connecting to server: %s:%u\n", md->server.host, 
        md->server.port);
    #endif

    md->server.connect_data = purple_proxy_connect(NULL, md->account, md->server.host,
                md->server.port, mrim_login_server_connected, md);

    if (!md->server.connect_data) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to connect to server"
        );
        return;
    }
}

static void 
mrim_login_balancer_connected(gpointer data, gint source, const gchar *error_message) {
    MrimData *md = (MrimData*) data;

    md->balancer.connect_data = NULL;
    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect to balancer %s", error_message);
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return;
    }

    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "balancer connected fd = %d\n", source);
    #endif
   
    md->balancer.fd = source;
    md->balancer.read_ih = purple_input_add(md->balancer.fd, PURPLE_INPUT_READ,
            mrim_login_balancer_answered, md);

    if (!md->balancer.read_ih) {
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
    MrimData *md;

    md = g_new0(MrimData, 1);
    md->account = account;
    md->account->gc->proto_data = md;
    md->balancer.port = (guint) purple_account_get_int(account, 
                "balancer_port", MRIMPRPL_BALANCER_DEFAULT_PORT);
    md->balancer.host = g_strdup(purple_account_get_string(account, 
                "balancer_host", MRIMPRPL_BALANCER_DEFAULT_HOST));
   
    purple_connection_set_state(md->account->gc, PURPLE_CONNECTING);

    #ifdef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "resolving balancer host %s:%u", 
                md->balancer.host, md->balancer.port);
    #endif

    md->balancer.connect_data = purple_proxy_connect(NULL, md->account, 
        md->balancer.host, md->balancer.port, mrim_login_balancer_connected, md);
    if (!md->balancer.connect_data) {
        purple_connection_error_reason(account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Unable to connect to balancer host"
        );
        return;
    }

    md->server.tx_buf = purple_circ_buffer_new(MRIM_CIRC_BUFFER_GROW);
    md->server.rx_buf = purple_circ_buffer_new(MRIM_CIRC_BUFFER_GROW);
    md->server.rx_pkt_buf = g_string_sized_new(MRIM_LINR_BUFFER_INIT);
}


/* Performs logout */
static void
mrim_free(MrimData *md)
{
    if (!md) {
        return;
    }

    /* Free balancer structures */
    if (md->balancer.host) {
        g_free(md->balancer.host);
        md->balancer.host = NULL;
    }
    md->balancer.port = 0;
    if (md->balancer.connect_data) {
        purple_proxy_connect_cancel(md->balancer.connect_data);
        md->balancer.connect_data = NULL;
    }
    md->balancer.fd = 0; /* is ther any need to close connections ? */
    if (md->balancer.read_ih) {
        purple_input_remove(md->balancer.read_ih);
        md->balancer.read_ih = 0;
    }
        
    /* Free server structures */
    if (md->server.host) {
        g_free(md->server.host);
        md->server.host = NULL;
    }
    md->server.port = 0;
    if (md->server.connect_data) {
        purple_proxy_connect_cancel(md->server.connect_data);
        md->server.connect_data = NULL;
    }
    md->server.fd = 0; /* is ther any need to close connections ? */
    if (md->server.read_ih) {
        purple_input_remove(md->server.read_ih);
        md->server.read_ih = 0;
    }
    if (md->server.write_ih) {
        purple_input_remove(md->server.write_ih);
        md->server.write_ih = 0;
    }
    if (md->server.rx_buf) {
        purple_circ_buffer_destroy(md->server.rx_buf);
        md->server.rx_buf = NULL;
    }
    if (md->server.rx_pkt_buf) {
        g_string_free(md->server.rx_pkt_buf, TRUE);
        md->server.rx_pkt_buf = NULL;
    }
    if (md->server.tx_buf) {
        purple_circ_buffer_destroy(md->server.tx_buf);
        md->server.tx_buf = NULL;
    }

    #ifndef ENABLE_MRIM_DEBUG
    purple_debug_info("mrim", "resources freeed\n");
    #endif
}

void 
mrim_close(PurpleConnection *gc)
{
    if (gc) {
        mrim_free(gc->proto_data);
    }
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
