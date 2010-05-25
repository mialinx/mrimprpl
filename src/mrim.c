#include "config.h"
#include <glib.h>
#include <purple.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include "mrim.h"
#include "pkt.h"
#include "cl.h"

#define MRIM_TYPING_TIMEOUT 10
#define MRIM_CIRC_BUFFER_GROW (16 * 1024)
#define MRIM_LINR_BUFFER_INIT (1024)

/**************************************************/
/************* ATTEMPTS ***************************/
/**************************************************/

typedef enum {
    ATMP_ADD_CONTACT,
    ATMP_REMOVE_CONTACT,
    ATMP_MOVE_CONTACT,
    ATMP_RENAME_CONTACT,
    ATMP_ADD_GROUP,
    ATMP_REMOVE_GROUP,
    ATMP_RENAME_GROUP,
    ATMP_MESSAGE
} MrimAttempType;

typedef struct {
    MrimAttempType type;
    union {
        struct {
            MrimContact *contact;
        } add_contact;
        struct {
            MrimContact *contact;
        } remove_contact;
        struct {
            MrimContact *contact;
            MrimGroup *group;
        } move_contact;
        struct {
            MrimContact *contact;
            gchar *new_nick;
        } rename_contact;
        struct {
            MrimGroup *group;
            gchar *buddy_to_add;
            gchar *buddy_to_move;
        } add_group;
        struct {
            MrimGroup *group;
        } remove_group;
        struct {
            MrimGroup *group;
            gchar *new_name;
        } rename_group;
        struct {
            gchar *name;
            gchar *message;
            PurpleMessageFlags flags;
        } message;
    };
} MrimAttempt;

static MrimAttempt *
_attempt_new(MrimAttempType type, ...)
{
    MrimAttempt *atmp = g_new0(MrimAttempt, 1);
    va_list rest;
   
    atmp->type = type;
    va_start(rest, type);
    switch (type) {
        case ATMP_ADD_CONTACT:
            atmp->add_contact.contact = va_arg(rest, MrimContact*);
            break;
        case ATMP_REMOVE_CONTACT:
            atmp->remove_contact.contact = va_arg(rest, MrimContact*);
            break;
        case ATMP_MOVE_CONTACT:
            atmp->move_contact.contact = va_arg(rest, MrimContact*);
            atmp->move_contact.group = va_arg(rest, MrimGroup*);
            break;
        case ATMP_RENAME_CONTACT:
            atmp->rename_contact.contact = va_arg(rest, MrimContact*);
            atmp->rename_contact.new_nick = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_ADD_GROUP:
            atmp->add_group.group = va_arg(rest, MrimGroup*);
            atmp->add_group.buddy_to_add = g_strdup(va_arg(rest, gchar*));
            atmp->add_group.buddy_to_move = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_REMOVE_GROUP:
            atmp->remove_group.group = va_arg(rest, MrimGroup*);
            break;
        case ATMP_RENAME_GROUP:
            atmp->rename_group.group = va_arg(rest, MrimGroup*);
            atmp->rename_group.new_name = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_MESSAGE:
            atmp->message.name = g_strdup(va_arg(rest, gchar*));
            atmp->message.message = g_strdup(va_arg(rest, gchar*));
            atmp->message.flags = va_arg(rest, PurpleMessageFlags);
            break;
    }
    va_end(rest);
    return atmp;
}

static void
_attempt_destroy(MrimAttempt *atmp)
{
    switch (atmp->type) {
        case ATMP_ADD_CONTACT:
            break;
        case ATMP_REMOVE_CONTACT:
            break;
        case ATMP_MOVE_CONTACT:
            break;
        case ATMP_RENAME_CONTACT:
            g_free(atmp->rename_contact.new_nick);
            break;
        case ATMP_ADD_GROUP:
            g_free(atmp->add_group.buddy_to_add);
            g_free(atmp->add_group.buddy_to_move);
            break;
        case ATMP_REMOVE_GROUP:
            break;
        case ATMP_RENAME_GROUP:
            g_free(atmp->rename_group.new_name);
            break;
        case ATMP_MESSAGE:
            g_free(atmp->message.name);
            g_free(atmp->message.message);
            break;
    }
    g_free(atmp);
}

static void
_attempt_free(void *ptr)
{
    if (ptr) {
        _attempt_destroy((MrimAttempt*) ptr);
    }
}

/**************************************************/
/************* CONTACT LIST ***********************/
/**************************************************/

static MrimGroup*
_cl_contact_get_group(MrimData *md, MrimContact *contact)
{
    MrimGroup *group;
    GList *item = g_hash_table_get_values(md->groups); 

    while (item) {
        group = (MrimGroup*) item->data;
        if (group->id == contact->group_id) {
            return group;
        }
        item = g_list_next(item);
    }

    return NULL;
}

/* =========================================== */

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
    /* TODO create images and logic for 'not-authorized' */
    return "emblem";
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

    type = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    type = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, 
            TRUE, TRUE, FALSE);
    list = g_list_append(list, type);

    return list;
}

static guint32
_status_purple2mrim(PurpleStatus *status)
{
    guint32 mrim_status = 0;
    PurpleStatusType *type = purple_status_get_type(status);
    switch (purple_status_type_get_primitive(type)) {
        case PURPLE_STATUS_AVAILABLE:
            return STATUS_ONLINE;
            break;
        case PURPLE_STATUS_AWAY:
            return STATUS_AWAY;
            break;
        case PURPLE_STATUS_INVISIBLE:
            return STATUS_ONLINE & STATUS_FLAG_INVISIBLE;
            break;
        default:
            if (purple_status_is_online(status)) {
                return STATUS_ONLINE;
            }
            else {
                return STATUS_OFFLINE;
            }
            break;
    }
}

static const gchar *
_status_mrim2purple(guint32 mrim_status)
{
    if (mrim_status & STATUS_FLAG_INVISIBLE) {
        return purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE);
    }
    else {
        mrim_status &= ~STATUS_FLAG_INVISIBLE;
    }
    switch (mrim_status) {
        case STATUS_ONLINE:
            return purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE);
            break;
        case STATUS_OFFLINE:
            return purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE);
            break;
        case STATUS_AWAY:
            return purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY);
            break;
        case STATUS_UNDETERMINATED:
        default:
            return purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET);
            break;
    }
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
_canwrite_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = (MrimData*) data;
    guint max_read = 0;
    gint bytes_written = 0;

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

    purple_input_remove(md->server.write_handle);
    md->server.write_handle = 0;
}

static void
_send_out(MrimData *md)
{
    if (!md->server.write_handle) {
        md->server.write_handle = purple_input_add(md->server.fd, PURPLE_INPUT_WRITE,
            _canwrite_cb, md);
        if (!md->server.write_handle) {
            purple_connection_error_reason(md->account->gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                "Failed to connect to server"
            );
        }
    }
}

/* Own keepalive */
static gboolean
_mrim_ping(gpointer data)
{
    MrimData *md = (MrimData *) data;

    mrim_pkt_build_ping(md);
    _send_out(md);
    purple_debug_info("mrim", "{%u} ping sent\n", (guint) md->tx_seq);
    return TRUE;
}

static void
_dispatch_hello_ack(MrimData *md, MrimPktHelloAck *pkt)
{
    const char *login, *pass, *agent;

    md->keepalive = pkt->timeout;

    purple_debug_info("mrim", "keepalive is %u\n", md->keepalive);

    login = purple_account_get_username(md->account);
    pass = purple_account_get_password(md->account);
    agent = "Mail.ru pidgin plugin v0.01";

    mrim_pkt_build_login(md, login, pass, STATUS_ONLINE, agent);
    _send_out(md);

    md->keepalive_handle = purple_timeout_add_seconds(md->keepalive, _mrim_ping, md);
    if (!md->keepalive_handle) {
        purple_connection_error_reason(
            md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "failed to start ping"
        );
    }
}

static void
_dispatch_login_ack(MrimData *md, MrimPktLoginAck *pkt)
{
    purple_debug_info("mrim", "login succeded\n");

    purple_connection_set_state(md->account->gc, PURPLE_CONNECTED);
}

static void
_dispatch_login_rej(MrimData *md, MrimPktLoginRej *pkt)
{
    purple_debug_info("mrim", "login failed\n");

    purple_connection_error_reason(
        md->account->gc,
        PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
        pkt->reason
    );
}

static void
_dispatch_message_ack(MrimData *md, MrimPktMessageAck *pkt)
{
    PurpleConversation *conv = NULL;
    PurpleConvIm *conv_im = NULL;

    purple_debug_info("mrim", "message from %s flags 0x%08x\n", pkt->from, (guint) pkt->flags);

    if (pkt->flags & MESSAGE_FLAG_NOTIFY) {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, pkt->from, md->account);
        if (!conv) {
            return;
        }
        conv_im = PURPLE_CONV_IM(conv);
        purple_conv_im_set_typing_state(conv_im, PURPLE_TYPING);
        purple_conv_im_start_typing_timeout(conv_im, MRIM_TYPING_TIMEOUT);
    }
    else {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, pkt->from, md->account);
        if (!conv) {
            conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, md->account, pkt->from);
        }
        purple_conversation_set_name(conv, pkt->from);
        purple_conversation_write(conv, pkt->from, pkt->message, PURPLE_MESSAGE_RECV, time(NULL));
    }

    if (!(pkt->flags & MESSAGE_FLAG_NORECV)) {
        mrim_pkt_build_message_recv(md, pkt->from, pkt->msg_id);
        _send_out(md);
    }
}

static void
_dispatch_message_status(MrimData *md, MrimPktMessageStatus *pkt)
{
    MrimAttempt *atmp;
    PurpleConversation *conv;

    if (!(atmp = g_hash_table_lookup(md->attempts, (gpointer) pkt->header.seq))) {
        purple_debug_error("mrim", "_dispatch_message_status: not attempt for message seq %u\n",
                                        pkt->header.seq);
        return;
    }
    if (atmp->type != ATMP_MESSAGE) {
        purple_debug_error("mrim", "_dispatch_message_status: incorrect attempt type\n");
        return;
    }

    if (pkt->status == MESSAGE_DELIVERED) {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, 
                                                atmp->message.name, md->account);
        if (!conv) {
            conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, md->account, atmp->message.name);
        }
        purple_conversation_write(conv, atmp->message.name, atmp->message.message, PURPLE_MESSAGE_SEND, time(NULL));

        g_hash_table_remove(md->attempts, (gpointer) pkt->header.seq);
    }
}

static void
_dispatch_connection_param(MrimData *md, MrimPktConnectionParams *pkt)
{
    md->keepalive = pkt->timeout;

    purple_debug_info("mrim", "keepalive period %u\n", (guint) pkt->timeout);

    if (md->keepalive_handle) {
        purple_timeout_remove(md->keepalive_handle);
    }

    md->keepalive_handle = purple_timeout_add_seconds(md->keepalive, _mrim_ping, md);
    if (!md->keepalive_handle) {
        purple_connection_error_reason(
            md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "failed to start ping"
        );
    }
}

static void
_dispatch_user_info(MrimData *md, MrimPktUserInfo *pkt)
{
    GList *item;
    const gchar *own_alias = purple_account_get_alias(md->account);
    const gchar *new_alias = g_hash_table_lookup(pkt->info, "MRIM.NICKNAME");
    
    for (item = g_hash_table_get_keys(pkt->info); item; item = g_list_next(item)) {
        purple_debug_misc("mrim", "user info '%s'='%s'\n", item->data, 
                        g_hash_table_lookup(pkt->info, item->data));
    }
    g_list_free(g_list_first(item));

    if ((new_alias && strlen(new_alias)) && !(own_alias && strlen(own_alias))) {
        purple_account_set_alias(md->account, new_alias);
    }
}

static const gchar*
_contact_operation_reason(guint32 status)
{
    switch (status) {
        case CONTACT_OPER_SUCCESS:
            return "Operation succeded";
            break;
        case CONTACT_OPER_ERROR:
            return "Incorrect data";
            break;
        case CONTACT_OPER_INTERR:
            return "Internal error";
            break;
        case CONTACT_OPER_NO_SUCH_USER:
            return "No such user";
            break;
        case CONTACT_OPER_INVALID_INFO:
            return "Incorrect user name";
            break;
        case CONTACT_OPER_USER_EXISTS:
            return "User already exists";
            break;
        case CONTACT_OPER_GROUP_LIMIT:
            return "Limit of groups exceeded";
            break;
        default:
            return "Unknown error";
            break;
    }
}

static void
_mrim_group_buddy(MrimData *md, const gchar *name, const gchar *old_group, const gchar *new_group);

static void
_mrim_add_buddy(MrimData *md, const gchar *name, const gchar *group_name);

static void
_dispatch_add_contact_ack(MrimData *md, MrimPktAddContactAck *pkt)
{
    purple_debug_info("mrim", "{%u} add contact ack status %u\n", pkt->header.seq, pkt->status);

    const gchar *reason = _contact_operation_reason(pkt->status);
    MrimAttempt *atmp = g_hash_table_lookup(md->attempts, (gpointer) pkt->header.seq);
    MrimContact *contact = NULL;
    MrimGroup *group = NULL;

    if (!atmp) {
        purple_debug_warning("mrim", "failed to find attempt for seq %u\n", (guint) pkt->header.seq);
        return;
    }

    if (atmp->type == ATMP_ADD_GROUP) {
        group = atmp->add_group.group;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_replace(md->groups, group->name, group);
            if (atmp->add_group.buddy_to_add) {
                _mrim_add_buddy(md, atmp->add_group.buddy_to_add, group->name);
            }
            else if (atmp->add_group.buddy_to_move) {
                _mrim_group_buddy(md, atmp->add_group.buddy_to_move, NULL, group->name);
            }
        }
        else if (pkt->status == CONTACT_OPER_USER_EXISTS) {
            purple_debug_info("mrim", "group already existed\n");
            mrim_group_destroy(group);
        }
        else {
            purple_notify_error(md->account->gc, "Adding group", 
                                        "Failed to create group on server", reason);
            purple_blist_remove_group(purple_find_group(group->name));
            mrim_group_destroy(group);
        }
    }

    else if (atmp->type == ATMP_ADD_CONTACT) {
        contact = atmp->add_contact.contact;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            contact->id = pkt->contact_id;
            g_hash_table_replace(md->contacts, contact->name, contact);
        }
        else if (pkt->status == CONTACT_OPER_USER_EXISTS) {
            purple_debug_info("mrim", "user already %s existed\n", contact->name);
            mrim_contact_destroy(contact);
        }
        else {
            purple_notify_error(md->account->gc, "Adding user", 
                                        "Failed to create user on server", reason);
            purple_blist_remove_buddy(purple_find_buddy(md->account, contact->name));
            mrim_contact_destroy(contact);
        }
    }
    
    else {
        purple_debug_warning("mrim", "unexpected type of attempt for seq %u\n", 
                                    (guint) pkt->header.seq);
    }

    g_hash_table_remove(md->attempts, (gpointer) pkt->header.seq);
}

static void
_dispatch_modify_contact_ack(MrimData *md, MrimPktModifyContactAck *pkt)
{
    purple_debug_info("mrim", "{%u} modify contact ack status %u\n", pkt->header.seq, pkt->status);

    const gchar *reason = _contact_operation_reason(pkt->status);
    MrimAttempt *atmp = g_hash_table_lookup(md->attempts, (gpointer) pkt->header.seq);
    MrimContact *contact = NULL;
    MrimGroup *group = NULL;

    if (!atmp) {
        purple_debug_warning("mrim", "failed to find attempt for seq %u\n", (guint) pkt->header.seq);
        return;
    }

    if (atmp->type == ATMP_REMOVE_GROUP) {
        group = atmp->remove_group.group;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_remove(md->groups, group->name);
        }
        else {
            purple_notify_error(md->account->gc, "Removing group", 
                                        "Failed to remove group on server", reason);
        }
    }

    else if (atmp->type == ATMP_RENAME_GROUP) {
        group = atmp->rename_group.group;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_steal(md->groups, group);
            g_free(group->name);
            group->name = g_strdup(atmp->rename_group.new_name);
            g_hash_table_replace(md->groups, group->name, group);
        }
        else {
            purple_notify_error(md->account->gc, "Modifing group",
                                        "Failed to modify group on server", reason);
            /* HOWTO rename group back ? */
        }
    }

    else if (atmp->type == ATMP_REMOVE_CONTACT) {
        contact = atmp->remove_contact.contact;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_remove(md->contacts, contact->name);
        }
        else {
            purple_notify_error(md->account->gc, "Removing user", 
                                        "Failed to remove user on server", reason);
            /* HOWTO undo deletion ? */
        }
    }
    
    else if (atmp->type == ATMP_MOVE_CONTACT) {
        contact = atmp->move_contact.contact;
        group = atmp->move_contact.group;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            contact->group_id = group->id;
        }
        else {
            purple_notify_error(md->account->gc, "Moving user",
                                        "Failed to move user on server", reason);
        }
    }

    else if (atmp->type = ATMP_RENAME_CONTACT) {
        contact = atmp->rename_contact.contact;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_free(contact->nick);
            contact->nick = g_strdup(atmp->rename_contact.new_nick);   
        }
        else {
            purple_notify_error(md->account->gc, "Renaming user",
                                        "Failed to rename user on server", reason);
        }
    }

    else {
        purple_debug_warning("mrim", "unexpected type of attempt for seq %u\n", 
                                    (guint) pkt->header.seq);
    }

    g_hash_table_remove(md->attempts, (gpointer) pkt->header.seq);
}

static void
_dispatch_user_status(MrimData *md, MrimPktUserStatus *pkt)
{
    purple_debug_info("mrim", "contact status changed %s to 0x%08x\n",
                        pkt->email, (guint) pkt->status);

    purple_prpl_got_user_status(md->account, pkt->email, 
                        _status_mrim2purple(pkt->status), NULL);
}

static void
_dispatch_logout(MrimData *md, MrimPktLogout *pkt)
{
    purple_connection_error_reason(md->account->gc,
        PURPLE_CONNECTION_ERROR_OTHER_ERROR,
        "Another host logged in with the same email"
    );
    purple_account_disconnect(md->account);
}

static void
_dispatch_contact_list(MrimData *md, MrimPktContactList *pkt)
{
    MrimGroup *mgroup = NULL;
    MrimContact *contact = NULL;
    PurpleGroup *group = NULL;
    PurpleBuddy *buddy = NULL;
    GList *item = NULL;

    if (pkt->status != GET_CONTACTS_OK) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to load contact list"
        );
        return;
    }
 
    g_hash_table_remove_all(md->groups);
    g_hash_table_remove_all(md->contacts);

    /* ensure groups */
    for (item = g_list_first(pkt->groups); item; item = g_list_next(item)) {
        mgroup = (MrimGroup*) item->data;
        if (!(mgroup->flags & CONTACT_FLAG_REMOVED)) {
            if (!(group = purple_find_group(mgroup->name))) {
                group = purple_group_new(mgroup->name);
                purple_blist_add_group(group, NULL);
            }
            g_hash_table_replace(md->groups, mgroup->name, mgroup);
            purple_debug_info("mrim", "contact_list: group: [%u] %s\n", mgroup->id, mgroup->name);
        }
        else {
            /* do not remove groups from pidgin blist as they may be used by another accounts */
            purple_debug_info("mrim", "contact_list: group: [%u] %s [removed]\n", mgroup->id, mgroup->name);
        }
    }

    /* remove all buddies */
    GSList *buddies = NULL, *sitem = NULL;
    buddies = sitem = purple_find_buddies(md->account, NULL);
    while (sitem) {
        buddy = (PurpleBuddy*) sitem->data;
        purple_blist_remove_buddy(buddy);
        sitem = g_slist_next(sitem);
    }
    g_slist_free(buddies);

    /* add buddies */
    for (item = g_list_first(pkt->contacts); item; item = g_list_next(item)) {
        contact = (MrimContact*) item->data;
        if (!(contact->flags & CONTACT_FLAG_REMOVED)) {
            buddy = purple_buddy_new(md->account, contact->name, contact->nick);
            mgroup = _cl_contact_get_group(md, contact);
            if (mgroup && !(mgroup->flags & CONTACT_FLAG_REMOVED)) {
                group = purple_find_group(mgroup->name);
            }
            else {
                group = NULL;
            }
            purple_blist_add_buddy(buddy, NULL, group, NULL);
            purple_prpl_got_user_status(md->account, contact->name, 
                                    _status_mrim2purple(contact->status), NULL);
            g_hash_table_replace(md->contacts, contact->name, contact);
            purple_debug_info("mrim", "contact_list: contact: [%u] %s (%s) group %u\n", 
                                       contact->id, contact->name, contact->nick, contact->group_id);
        }
    }

}

static void
_dispatch(MrimData *md, MrimPktHeader *pkt)
{
    switch (pkt->msg) {
        case MRIM_CS_HELLO_ACK:
            _dispatch_hello_ack(md, (MrimPktHelloAck*) pkt);
            break;
        case MRIM_CS_LOGIN_ACK:
            _dispatch_login_ack(md, (MrimPktLoginAck*) pkt);
            break;
        case MRIM_CS_LOGIN_REJ:
            _dispatch_login_rej(md, (MrimPktLoginRej*) pkt);
            break;
        case MRIM_CS_MESSAGE_ACK:
            _dispatch_message_ack(md, (MrimPktMessageAck*) pkt);
            break;
        case MRIM_CS_MESSAGE_STATUS:
            _dispatch_message_status(md, (MrimPktMessageStatus*) pkt);
            break;
        case MRIM_CS_USER_STATUS:
            _dispatch_user_status(md, (MrimPktUserStatus*) pkt);
            break;
        case MRIM_CS_LOGOUT:
            _dispatch_logout(md, (MrimPktLogout*) pkt);
            break;
        case MRIM_CS_CONNECTION_PARAMS:
            _dispatch_connection_param(md, (MrimPktConnectionParams*) pkt);
            break;
        case MRIM_CS_USER_INFO:
            _dispatch_user_info(md, (MrimPktUserInfo*) pkt);
            break;
        case MRIM_CS_ADD_CONTACT_ACK:
            _dispatch_add_contact_ack(md, (MrimPktAddContactAck*) pkt);
            break;
        case MRIM_CS_MODIFY_CONTACT_ACK:
            _dispatch_modify_contact_ack(md, (MrimPktModifyContactAck*) pkt);
            break;
        case MRIM_CS_OFFLINE_MESSAGE_ACK:
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            break;
        case MRIM_CS_MPOP_SESSION:
            break;
        case MRIM_CS_ANKETA_INFO:
            break;
        case MRIM_CS_CONTACT_LIST2:
            _dispatch_contact_list(md, (MrimPktContactList*) pkt);
            break;
        default:
            break;
    }
}

static void
_canread_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = NULL;
    gint bytes_read = 0;
    #define MRIM_ITERM_BUFF_LEN (4 * 1024)
    gchar buff[MRIM_ITERM_BUFF_LEN];
    MrimPktHeader *pkt = NULL;

    md = (MrimData*) data;
    while ((bytes_read = read(source, buff, MRIM_ITERM_BUFF_LEN)) > 0) {
        purple_circ_buffer_append(md->server.rx_buf, buff, bytes_read);
    }

    if (bytes_read == 0 || (bytes_read < 0 && errno != EWOULDBLOCK)) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Server connection was lost"
        );
        purple_input_remove(md->server.read_handle);
        md->server.read_handle = 0;
    }
    else {
        while (pkt = mrim_pkt_parse(md)) {
            _dispatch(md, pkt);
            if (pkt->msg == MRIM_CS_LOGOUT) {
                mrim_pkt_free(pkt);
                break;
            }
            else {
                mrim_pkt_free(pkt);
            }
        }
    }
}


/* Perform login */
static void
_mrim_login_server_connected(gpointer data, gint source, const gchar *error_message)
{
    MrimData *md = (MrimData*) data;

    md->server.connect_data = NULL;
    if (source < 0) {
        gchar *tmp = g_strdup_printf("Failed to connect to server: %s\n", error_message);
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp
        );
        g_free(tmp);
        return;
    }

    purple_debug_info("mrim", "server connected fd = %d\n", source);

    md->server.fd = source;
    md->server.read_handle = purple_input_add(md->server.fd, PURPLE_INPUT_READ,
        _canread_cb, md);
    if (!md->server.read_handle) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to connect to server"
        );
        return;
    }

    mrim_pkt_build_hello(md);
    _send_out(md);
}

static void
_mrim_login_balancer_answered(gpointer data, gint source, PurpleInputCondition cond)
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
    purple_input_remove(md->balancer.read_handle);
    md->balancer.read_handle = 0;
    close(md->balancer.fd);
    md->balancer.fd = 0;

    purple_debug_info("mrim", "connecting to server: %s:%u\n", 
                                    md->server.host, md->server.port);

    md->server.connect_data = purple_proxy_connect(NULL, md->account, md->server.host,
                md->server.port, _mrim_login_server_connected, md);

    if (!md->server.connect_data) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to connect to server"
        );
        return;
    }
}

static void 
_mrim_login_balancer_connected(gpointer data, gint source, const gchar *error_message) {
    MrimData *md = (MrimData*) data;

    md->balancer.connect_data = NULL;
    if (source < 0) {
        gchar *tmp = g_strdup_printf("Unable to connect to balancer %s", error_message);
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR, tmp);
        g_free(tmp);
        return;
    }

    purple_debug_info("mrim", "balancer connected fd = %d\n", source);
   
    md->balancer.fd = source;
    md->balancer.read_handle = purple_input_add(md->balancer.fd, PURPLE_INPUT_READ,
            _mrim_login_balancer_answered, md);

    if (!md->balancer.read_handle) {
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

    purple_debug_info("mrim", "resolving balancer host %s:%u\n", 
                                    md->balancer.host, md->balancer.port);

    md->balancer.connect_data = purple_proxy_connect(NULL, md->account, 
        md->balancer.host, md->balancer.port, _mrim_login_balancer_connected, md);
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
  
    md->tx_seq = 0;
    md->keepalive = 0;
    md->keepalive_handle =0;
    md->attempts = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, _attempt_free);
    md->groups = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, mrim_group_free);
    md->contacts = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, mrim_contact_free);
}


/* Performs logout */
void 
mrim_close(PurpleConnection *gc)
{
    MrimData *md = (MrimData*) gc->proto_data;

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
    if (md->balancer.read_handle) {
        purple_input_remove(md->balancer.read_handle);
        md->balancer.read_handle = 0;
    }
    if (md->balancer.fd) {
        close(md->balancer.fd);
        md->balancer.fd = 0;
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
    if (md->server.read_handle) {
        purple_input_remove(md->server.read_handle);
        md->server.read_handle = 0;
    }
    if (md->server.write_handle) {
        purple_input_remove(md->server.write_handle);
        md->server.write_handle = 0;
    }
    if (md->server.fd) {
        close(md->server.fd);
        md->server.fd = 0;
    }

    /* Free buffers */
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

    /* reset tx sequence number */
    md->tx_seq = 0;
    if (md->keepalive_handle) {
        purple_timeout_remove(md->keepalive_handle);
        md->keepalive_handle = 0;
    }
    md->keepalive = 0;
    g_hash_table_destroy(md->groups);
    md->groups = NULL;
    g_hash_table_destroy(md->contacts);
    md->contacts = NULL;
    g_hash_table_destroy(md->attempts);
    md->attempts = NULL;

    purple_debug_info("mrim", "resources were freeed\n");
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
    MrimData *md = (MrimData*) gc->proto_data;
    MrimContact *contact = NULL;
    MrimAttempt *atmp = NULL;
    guint32 mrim_flags = 0;
    gchar *clean = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, who, NULL, (gpointer*) &contact)) {
        purple_debug_info("mrim", "send_im: failed to find mrim contact for %s\n", who);
    }

    clean = purple_unescape_html(strlen(message) > 0 ? message : " ");
    mrim_pkt_build_message(md, mrim_flags, who, clean, " ");
    _send_out(md);
    g_free(clean);

    atmp = _attempt_new(ATMP_MESSAGE, who, message, mrim_flags);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} sending message to %s\n", who);
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
    MrimData *md = (MrimData*) gc->proto_data;
    guint32 mrim_flags = MESSAGE_FLAG_NORECV|MESSAGE_FLAG_NOTIFY;
    if (state = PURPLE_TYPING) {
        mrim_pkt_build_message(md, mrim_flags, name, " ", " ");
        _send_out(md);
        return MRIM_TYPING_TIMEOUT;
    }
    else {
        return 0;
    }
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
    MrimData *md = (MrimData*) account->gc->proto_data;
    guint32 mrim_status = _status_purple2mrim(status);
    if (mrim_status != STATUS_UNDETERMINATED && mrim_status != STATUS_OFFLINE) {
        mrim_pkt_build_change_status(md, mrim_status);
        _send_out(md);
    }
    else {
        purple_debug_error("mrim", "unexpected status %s\n", purple_status_get_id(status));
    }
}

/* set idle time */
void 
mrim_set_idle(PurpleConnection *gc, int idletime)
{
}

static void
_mrim_add_group(MrimData *md, const gchar *name, const gchar *buddy_to_add, 
                            const gchar *buddy_to_move)
{
    guint32 group_count = g_hash_table_size(md->groups);
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    group = mrim_group_new(0, 0, name);

    mrim_pkt_build_add_contact(md, CONTACT_FLAG_GROUP | (group_count << 24), 0, 
                                    group->name, group->name);
    _send_out(md);

    atmp = _attempt_new(ATMP_ADD_GROUP, group, buddy_to_add, buddy_to_move);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} adding group %s\n\tpending add %s pending move %s\n", 
                            (guint) md->tx_seq, group->name, buddy_to_add, buddy_to_move);
}

static void
_mrim_add_buddy(MrimData *md, const gchar *name, const gchar *group_name)
{
    PurpleBuddy *buddy = NULL;
    MrimContact *contact = NULL;
    MrimAttemp *atmp = NULL;
    MrimGroup *group = NULL;
    
    if (!g_hash_table_lookup_extended(md->groups, group_name, NULL, (gpointer*) &group)) {
        _mrim_add_group(md, group_name, name, NULL);
        return;
    }
    if (!(buddy = purple_find_buddy(md->account, name))) {
        purple_debug_error("mrim", "_mrim_add_buddy: failed to find buddy for %s\n", name);
        return;
    }
    
    contact = mrim_contact_new(0, 0, CONTACT_INTFLAG_NOT_AUTHORIZED, STATUS_OFFLINE, group->id,
                                purple_buddy_get_name(buddy), purple_buddy_get_alias(buddy));
    
    atmp = _attempt_new(ATMP_ADD_CONTACT, contact);

    mrim_pkt_build_add_contact(md, 0, group->id, contact->name, contact->nick);
    _send_out(md);
    
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} adding user %s to group %s (%u)\n", (guint) md->tx_seq, 
                                    contact->name, group->name, (guint) group->id);
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
    _mrim_add_buddy((MrimData*) gc->proto_data, purple_buddy_get_name(buddy),
                                purple_group_get_name(group));
}

static void
_mrim_remove_buddy(MrimData *md, const gchar* name)
{
    MrimContact *contact = NULL;
    MrimAttemp *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, name, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "remove buddy: failed to find mrim contact for %s\n", name);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags | CONTACT_FLAG_REMOVED, 
                                    contact->group_id, contact->name, contact->nick);
    _send_out(md);

    atmp = _attempt_new(ATMP_REMOVE_CONTACT, contact);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} removing user %s\n", (guint) md->tx_seq, contact->name);
}

/* Remove one buddy from a contact list */
void 
mrim_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    _mrim_remove_buddy((MrimData*) gc->proto_data, purple_buddy_get_name(buddy));
}

static void
_mrim_alias_buddy(MrimData *md, const gchar *name, const gchar *old_alias, const gchar *new_alias)
{
    MrimContact *contact = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, name, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "renaming buddy: failed to find mrim user for %s\n", name);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags, contact->group_id, contact->name, new_alias);
    _send_out(md);

    atmp = _attempt_new(ATMP_RENAME_CONTACT, contact, new_alias);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} renaming user %s (%u) to %s\n", (guint) md->tx_seq, 
                                contact->name, contact->id, new_alias);
}

/* Change a buddy alias on a server */
void 
mrim_alias_buddy(PurpleConnection *gc, const char *who, const char *alias)
{
    _mrim_alias_buddy((MrimData*) gc->proto_data, who, NULL, alias);
}

/* Change a buddy group on a server */
static void
_mrim_group_buddy(MrimData *md, const gchar *name, const gchar *old_group, const gchar *new_group)
{
    MrimContact *contact = NULL;
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, name, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "group_buddy: failed to find mrim contact for %s\n", name);
        return;
    }
    if (!g_hash_table_lookup_extended(md->groups, new_group, NULL, (gpointer*) &group)) {
        _mrim_add_group(md, new_group, NULL, name);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags, group->id, contact->name, contact->nick);
    _send_out(md);

    atmp = _attempt_new(ATMP_MOVE_CONTACT, contact, group);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} moving user %s to group %s (%u)\n", (guint) md->tx_seq, 
                                contact->name, group->name, (guint) group->id);
}

void 
mrim_group_buddy(PurpleConnection *gc, const gchar *name, 
                                        const gchar *old_group, const gchar *new_group)
{
    _mrim_group_buddy((MrimData*) gc->proto_data, name, old_group, new_group);
}

/* Rename group on a server side */
static void
_mrim_rename_group(MrimData *md, const gchar *old_name, const gchar *new_name)
{
    MrimGroup *group = NULL;
    MrimAttemp *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->groups, old_name, NULL, (gpointer*) &group)) {
        purple_debug_info("mrim", "rename group: failed to find group in contact list for %s\n", 
                                        old_name);
        return;
    }

    mrim_pkt_build_modify_contact(md, group->id, group->flags | CONTACT_FLAG_GROUP, 0, new_name, new_name);
    _send_out(md);

    atmp = _attempt_new(ATMP_RENAME_GROUP, group, new_name);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp); 

    purple_debug_info("mrim", "{%u} renaming group %u from %s to %s\n", (guint) md->tx_seq,
                                group->id, group->name, new_name);
}

void 
mrim_rename_group(PurpleConnection *gc, const char *old_name, PurpleGroup *group, GList *moved_buddies)
{
    _mrim_rename_group((MrimData*) gc->proto_data, old_name, purple_group_get_name(group));
}

/*
 * Convert the username @a who to its canonical form.  (For example,
 * AIM treats "fOo BaR" and "foobar" as the same user; this function
 * should return the same normalized string for both of those.)
 */
const char *
mrim_normalize(const PurpleAccount *account, const char *who)
{
    #define MRIM_NORMALIZE_BUF_LEN 1024
    static gchar buf[MRIM_NORMALIZE_BUF_LEN];
    char *tmp = g_ascii_strdown(who, -1);
    g_snprintf(buf, sizeof(buf), "%s", tmp);
    g_free(tmp);
    buf[MRIM_NORMALIZE_BUF_LEN - 1] = '\0';
    return buf;
}

/* Removes group from a server */ 
static void
_mrim_remove_group(MrimData *md, const gchar *name)
{
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->groups, name, NULL, (gpointer*) &group)) {
        purple_debug_error("mrim", "remove group: failed to find group in contact list %s\n", name);
        return;
    }

    mrim_pkt_build_modify_contact(md, group->id, group->flags | CONTACT_FLAG_REMOVED | CONTACT_FLAG_GROUP, 0, 
                                group->name, group->name);
    _send_out(md);

    atmp = _attempt_new(ATMP_REMOVE_GROUP, group);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} removing group %s\n", (guint) md->tx_seq, group->name);
}

void 
mrim_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
    _mrim_remove_group((MrimData*) gc->proto_data, purple_group_get_name(group));
}

gboolean 
mrim_offline_message(const PurpleBuddy *buddy)
{
    return TRUE;
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
