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

#define MRIM_MAX_MESSAGE_LEN (8 * 1024 * 1024)
#define MRIM_TYPING_TIMEOUT 10
#define MRIM_CIRC_BUFFER_GROW (16 * 1024)
#define MRIM_LINR_BUFFER_INIT (1024)
#define MRIM_AVATAR_MAX_FAILS 3
#define MRIM_AVATAR_DELAY     2000
#define MRIM_EMAIL_BUF_LEN 1024
#define BIG_NUM 0xF0000000  // number big enougth, to prevent tx_seq to reach it


/**************************************************/
/************* MINOR UTILS ************************/
/**************************************************/

static void
ghf_dump(gpointer key, gpointer val, gpointer udata)
{
   fprintf(stderr, "%s %s -> %s\n", udata, key, val); 
}

static gboolean
is_chat_email(const char *email)
{
    return email && g_str_has_suffix(email, "@chat.agent");
}

static gint
chat_email2id(const char *email)
{
    if (!is_chat_email) {
        return 0;
    }
    return atoi(email);
}

static gchar*
chat_id2email(gint id)
{
    static gchar buf[MRIM_EMAIL_BUF_LEN];
    g_snprintf(buf, sizeof(buf), "%u@chat.agent", id);
    buf[MRIM_EMAIL_BUF_LEN - 1] = '\0';
    return buf;
}

static gboolean
is_temp_chat_email(const char *email)
{
    return email && g_str_has_suffix(email, "@temporary");
}

/**************************************************/
/************* CONTACT LIST ***********************/
/**************************************************/

MrimGroup*
mrim_group_new(const guint32 id, const guint32 flags, const gchar *nick)
{
    MrimGroup *group = g_new0(MrimGroup, 1);
    group->id = id;
    group->flags = flags;
    group->nick = g_strdup(nick);
    return group;
}

static void
_mrim_group_destroy(MrimGroup* group)
{
    g_free(group->nick);
    g_free(group);
}

static void
_mrim_group_free(gpointer ptr)
{
    _mrim_group_destroy((MrimGroup*) ptr);
}

MrimContact*
mrim_contact_new(const guint32 id, const guint32 flags, const guint32 server_flags, 
            const guint32 status, const guint32 group_id, const gchar *email, const gchar *nick)
{
    MrimContact *contact = g_new0(MrimContact, 1);
    contact->id = id;
    contact->flags = flags;
    contact->server_flags = server_flags;
    contact->status = status;
    contact->group_id = group_id;
    contact->email = g_strdup(email);
    contact->nick = g_strdup(nick);
    return contact;
}

static void
_mrim_contact_destroy(MrimContact *contact)
{
    g_free(contact->email);
    g_free(contact->nick);
    g_free(contact);
}

static void
_mrim_contact_free(gpointer ptr)
{
    _mrim_contact_destroy((MrimContact*) ptr);
}

static guint
_mrim_contact_email2id(MrimData *md, const gchar* email)
{
    if (!email || email[0] == '\0') {
        return 0;
    }
    MrimContact* contact = g_hash_table_lookup(md->contacts, email);
    return contact ? contact->id : 0;
}

static MrimGroup*
_mrim_contact_get_group(MrimData *md, MrimContact *contact)
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

static MrimData*
_mrim_data_from_buddy(PurpleBuddy *buddy)
{
    PurpleAccount *account = NULL;
    PurpleConnection *gc = NULL;
    MrimData *md = NULL;

    if (account = purple_buddy_get_account(buddy)) {
        if (gc = purple_account_get_connection(account)) {
            return (MrimData*) gc->proto_data;
        }
    }
    return NULL;
}

static MrimData*
_mrim_data_from_chat(PurpleChat *chat)
{
    PurpleAccount *account = NULL;
    PurpleConnection *gc = NULL;
    MrimData *md = NULL;

    if (account = purple_chat_get_account(chat)) {
        if (gc = purple_account_get_connection(account)) {
            return (MrimData*) gc->proto_data;
        }
    }
    return NULL;
}

static MrimContact*
_mrim_contact_from_buddy(PurpleBuddy *buddy) 
{
    MrimData *md = NULL;
    MrimContact *contact = NULL;

    if (md = _mrim_data_from_buddy(buddy)) {
        return (MrimContact*) g_hash_table_lookup(md->contacts, purple_buddy_get_name(buddy));
    }
    return NULL;
}

static MrimContact*
_mrim_contact_from_chat(PurpleChat *chat) 
{
    MrimData *md = NULL;
    MrimContact *contact = NULL;
    gchar *email = NULL;

    if (md = _mrim_data_from_chat(chat)) {
        email = g_hash_table_lookup(purple_chat_get_components(chat), "email");
        if (!email) {
            return NULL;
        }
        return (MrimContact*) g_hash_table_lookup(md->contacts, email);
    }
    return NULL;
}


static void
_mrim_contact_set_nick(MrimContact *contact, const gchar *new_nick)
{
    if (contact && contact->nick && new_nick) {
        g_free(contact->nick);
        contact->nick = g_strdup(new_nick);
    }
}

static void
_mrim_group_rename(MrimData *md, MrimGroup *group, const gchar *new_nick)
{
    if (md && group && new_nick) {
        g_hash_table_steal(md->groups, group->nick);
        g_free(group->nick);
        group->nick = g_strdup(new_nick);
        g_hash_table_replace(md->groups, group->nick, group);
    }
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

PurpleChat*
mrim_find_blist_chat(PurpleAccount *account, const char *email)
{
    PurpleBlistNode *node, *group;
    PurpleChat *chat;
    GHashTable *components;
    gchar *chat_email;

    if (!email || email[0] == '\0') {
        return NULL;
    }

    for (group = purple_blist_get_root(); 
         group != NULL; 
         group = purple_blist_node_next(group, TRUE)) 
    {
        for (node = purple_blist_node_get_first_child(group);
             node != NULL; 
             node = purple_blist_node_next(node, TRUE)) 
        {
            if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
                chat = (PurpleChat*) node;
                // f***king pidgin may use chat alias as name, 
                // so name may be not email, but alias 
                if (is_chat_email(email) || is_temp_chat_email(email)) { 
                    components = purple_chat_get_components(chat);
                    chat_email = g_hash_table_lookup(components, "email");
                }
                else {
                    chat_email = (gchar*) purple_chat_get_name(chat);
                }
                if (account == purple_chat_get_account(chat) 
                    && chat_email && email && !strcmp(chat_email, email)) 
                {
                    return chat;
                }
            }
        }
    }
    return NULL;
}

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
    ATMP_MESSAGE,
    ATMP_CONTACT_INFO,
    ATMP_CONTACT_SEARCH,
    ATMP_CREATE_CHAT,
    ATMP_ACCEPT_CHAT1,
    ATMP_ACCEPT_CHAT2,
    ATMP_REMOVE_CHAT,
    ATMP_RENAME_CHAT,
    ATMP_INVITE_USER
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
            gchar *new_nick;
        } rename_group;
        struct {
            gchar *email;
            gchar *message;
            guint32 flags;
        } message;
        struct {
            gchar *email;
        } contact_info;
        struct {
            guint32 unused;
        } contact_search;
        struct {
            gchar *email;
        } create_chat;
        struct {
            void *nothing;
        } accept_chat1;
        struct {
            gchar *email;
            gchar *nick;
        } accept_chat2;
        struct {
            gchar *email;
        } add_chat;
        struct {
            MrimContact *contact;
            PurpleChat *chat;
        } remove_chat;
        struct {
            MrimContact *contact;
            gchar* new_nick;
        } rename_chat;
        struct {
            gchar *email;
            gchar *who;
        } invite_user;
    };
} MrimAttempt;

static MrimAttempt *
_mrim_attempt_new(MrimAttempType type, ...)
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
            atmp->rename_group.new_nick = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_MESSAGE:
            atmp->message.email = g_strdup(va_arg(rest, gchar*));
            atmp->message.message = g_strdup(va_arg(rest, gchar*));
            atmp->message.flags = va_arg(rest, guint32);
            break;
        case ATMP_CONTACT_INFO:
            atmp->contact_info.email = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_CONTACT_SEARCH:
            break;
        case ATMP_CREATE_CHAT:
            atmp->create_chat.email = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_ACCEPT_CHAT1:
            break;
        case ATMP_ACCEPT_CHAT2:
            atmp->accept_chat2.email = g_strdup(va_arg(rest, gchar*));
            atmp->accept_chat2.nick = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_REMOVE_CHAT:
            atmp->remove_chat.contact = va_arg(rest, MrimContact*);
            break;
        case ATMP_RENAME_CHAT:
            atmp->rename_chat.contact = va_arg(rest, MrimContact*);
            atmp->rename_chat.new_nick = g_strdup(va_arg(rest, gchar*));
            break;
        case ATMP_INVITE_USER:
            atmp->invite_user.email = g_strdup(va_arg(rest, gchar*));
            atmp->invite_user.who = g_strdup(va_arg(rest, gchar*));
            break;
    }
    va_end(rest);
    return atmp;
}

static void
_mrim_attempt_destroy(MrimAttempt *atmp)
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
            g_free(atmp->rename_group.new_nick);
            break;
        case ATMP_MESSAGE:
            g_free(atmp->message.email);
            g_free(atmp->message.message);
            break;
        case ATMP_CONTACT_INFO:
            g_free(atmp->contact_info.email);
            break;
        case ATMP_CONTACT_SEARCH:
            break;
        case ATMP_CREATE_CHAT:
            g_free(atmp->create_chat.email);
            break;
        case ATMP_ACCEPT_CHAT1:
            break;
        case ATMP_ACCEPT_CHAT2:
            g_free(atmp->accept_chat2.email);
            g_free(atmp->accept_chat2.nick);
            break;
        case ATMP_REMOVE_CHAT:
            break;
        case ATMP_RENAME_CHAT:
            g_free(atmp->rename_chat.new_nick);
            break;
        case ATMP_INVITE_USER:
            g_free(atmp->invite_user.email);
            g_free(atmp->invite_user.who);
            break;
    }
    g_free(atmp);
}

static void
_mrim_attempt_free(void *ptr)
{
    if (ptr) {
        _mrim_attempt_destroy((MrimAttempt*) ptr);
    }
}

/**************************************************/
/************* CONNECTION *************************/
/**************************************************/

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
_dispatch(MrimData *md, MrimPktHeader *pkt);

static void
_canread_cb(gpointer data, gint source, PurpleInputCondition cond)
{
    MrimData *md = NULL;
    gint bytes_read = 0;
    guint bytes_unparsed = 0;
    #define MRIM_ITERM_BUFF_LEN (4 * 1024)
    gchar buff[MRIM_ITERM_BUFF_LEN];
    MrimPktHeader *pkt = NULL;

    md = (MrimData*) data;
    while ((bytes_read = read(source, buff, MRIM_ITERM_BUFF_LEN)) > 0) {
        purple_circ_buffer_append(md->server.rx_buf, buff, bytes_read);
    }
    bytes_unparsed = purple_circ_buffer_get_max_read(md->server.rx_buf);

    if ((bytes_read < 0 && errno != EWOULDBLOCK) || // real error 
        (bytes_read == 0 && bytes_unparsed == 0))   // we reached EOF and parsed last packet
    {
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
    md->attempts = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, _mrim_attempt_free);
    md->groups = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _mrim_group_free);
    md->contacts = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, _mrim_contact_free);
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

/**************************************************/
/************* GROUP MANIPULATION *****************/
/**************************************************/

static void
_mrim_add_group(MrimData *md, const gchar *nick, const gchar *buddy_to_add, 
                            const gchar *buddy_to_move)
{
    guint32 group_count = g_hash_table_size(md->groups);
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    group = mrim_group_new(0, 0, nick);

    mrim_pkt_build_add_contact(md, CONTACT_FLAG_GROUP | (group_count << 24), 0, 
                                    group->nick, group->nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_ADD_GROUP, group, buddy_to_add, buddy_to_move);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} adding group %s\n\tpending add %s pending move %s\n", 
                            (guint) md->tx_seq, group->nick, buddy_to_add, buddy_to_move);
}

static void
_mrim_rename_group(MrimData *md, const gchar *old_nick, const gchar *new_nick)
{
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->groups, old_nick, NULL, (gpointer*) &group)) {
        purple_debug_info("mrim", "rename group: failed to find group in contact list for %s\n", 
                                        old_nick);
        return;
    }

    mrim_pkt_build_modify_contact(md, group->id, group->flags | CONTACT_FLAG_GROUP, 0, new_nick, new_nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_RENAME_GROUP, group, new_nick);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp); 

    purple_debug_info("mrim", "{%u} renaming group %u from %s to %s\n", (guint) md->tx_seq,
                                group->id, group->nick, new_nick);
}

void 
mrim_rename_group(PurpleConnection *gc, const char *old_nick, PurpleGroup *group, GList *moved_buddies)
{
    _mrim_rename_group((MrimData*) gc->proto_data, old_nick, purple_group_get_name(group));
}

/* Removes group from a server */ 
static void
_mrim_remove_group(MrimData *md, const gchar *nick)
{
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->groups, nick, NULL, (gpointer*) &group)) {
        purple_debug_error("mrim", "remove group: failed to find group in contact list %s\n", nick);
        return;
    }

    mrim_pkt_build_modify_contact(md, group->id, group->flags | CONTACT_FLAG_REMOVED | CONTACT_FLAG_GROUP, 0, 
                                group->nick, group->nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_REMOVE_GROUP, group);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} removing group %s\n", (guint) md->tx_seq, group->nick);
}

void 
mrim_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
    _mrim_remove_group((MrimData*) gc->proto_data, purple_group_get_name(group));
}

/**************************************************/
/************* MESSAGING **************************/
/**************************************************/

static int
_mrim_send_message(MrimData *md, const gchar *who, const gchar *message, guint32 mrim_flags)
{
    MrimAttempt *atmp = NULL;
    gchar *clean = NULL;

    clean = purple_unescape_html(message && strlen(message) > 0 ? message : " ");
    if (strlen(clean) >= MRIM_MAX_MESSAGE_LEN) {
        return -E2BIG;
    }

    mrim_pkt_build_message(md, mrim_flags, who, clean, " ");
    _send_out(md);

    g_free(clean);
    if (!(mrim_flags & MESSAGE_FLAG_NORECV)) {
        atmp = _mrim_attempt_new(ATMP_MESSAGE, who, message, mrim_flags);
        g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);
    }

    purple_debug_info("mrim", "{%u} sending message to %s\n", (guint) md->tx_seq, who);
    return 0;
}

int
mrim_send_im(PurpleConnection *gc, const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
    MrimData *md = (MrimData*) gc->proto_data;
    MrimContact *contact = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, who, NULL, (gpointer*) &contact)) {
        purple_debug_info("mrim", "send_im: failed to find mrim contact for %s\n", who);
    }
    
    return _mrim_send_message(md, who, message, 0);
}

unsigned int 
mrim_send_typing(PurpleConnection *gc, const char *email, PurpleTypingState state)
{
    if (state = PURPLE_TYPING) {
        _mrim_send_message((MrimData*) gc->proto_data, email, " ", 
                            MESSAGE_FLAG_NOTIFY|MESSAGE_FLAG_NORECV);
        return MRIM_TYPING_TIMEOUT;
    }
    else {
        return 0;
    }
}

/**************************************************/
/************* AUTHORIZATION **********************/
/**************************************************/

typedef struct {
    MrimData *md;
    gchar *email;
} MrimAuthParams;

static MrimAuthParams*
_mrim_auth_params_new(MrimData *md, const gchar* email)
{
    MrimAuthParams *params = g_new0(MrimAuthParams, 1);
    params->md = md;
    params->email = g_strdup(email);
    return params;
}

static void
_mrim_auth_params_free(MrimAuthParams *params)
{
    if (params) {
        g_free(params->email);
        g_free(params);
    }
}

static void
_mrim_request_authorization_cb(gpointer ptr, gchar *message)
{
    MrimAuthParams *params = (MrimAuthParams*) ptr;
    _mrim_send_message(params->md, params->email, message, MESSAGE_FLAG_AUTHORIZE);
    _mrim_auth_params_free(params);
}

static void
_mrim_request_authorization_dialog(MrimData *md, const gchar *email)
{
     gchar *msg = g_strdup_printf("Request was sent to %s", email);
    _mrim_send_message(md, email, " ", MESSAGE_FLAG_AUTHORIZE);
    purple_notify_info(md->account->gc, "Authorization", msg, NULL);
    g_free(msg);
}

static void
_mrim_request_authorization_menu_cb(PurpleBlistNode *node, gpointer ptr)
{
    MrimAuthParams *params = (MrimAuthParams*) ptr;
    _mrim_request_authorization_dialog(params->md, params->email);
    _mrim_auth_params_free(params);
}

static void
_mrim_authorize(MrimData *md, const gchar *email)
{
    mrim_pkt_build_authorize(md, email);
    _send_out(md);

    purple_debug_info("mrim", "{%u} authorizing %s\n", (guint) md->tx_seq, email);
}

static void
_mrim_authorize_cb(gpointer ptr)
{
    MrimAuthParams *params = (MrimAuthParams*) ptr;
    _mrim_authorize(params->md, params->email);
    _mrim_auth_params_free(params);
}

/**************************************************/
/************* AVATARS FETCHING *******************/
/**************************************************/

typedef struct {
    MrimData *md;
    gchar *email;
    gchar *url;
    guint fails;
} MrimAvatarRequest;

static void 
_mrim_fetch_avatar_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
                    const gchar *url_text, gsize len, const gchar *error_message);

gboolean
_mrim_fetch_avatar_delayed(gpointer ptr)
{
    MrimAvatarRequest *ar = (MrimAvatarRequest*) ptr;
    purple_util_fetch_url(ar->url, TRUE, NULL, TRUE, _mrim_fetch_avatar_cb, ar);
    return FALSE;
}

static void 
_mrim_fetch_avatar_cb(PurpleUtilFetchUrlData *url_data, gpointer user_data,
                    const gchar *url_text, gsize len, const gchar *error_message) 
{
    MrimAvatarRequest *ar = (MrimAvatarRequest*) user_data;
    if (url_text) {
        void *img = g_memdup(url_text, len);
        purple_buddy_icon_new(ar->md->account, ar->email, img, len, NULL);
        // TODO : need we free img structure
        g_free(ar->email);
        g_free(ar->url);
        g_free(ar);
    }
    else {
        ar->fails++;
        purple_debug_info("mrim", "avatar download failed %u times for %s: %s\n", ar->fails, ar->email, error_message);
        if (++ar->fails < MRIM_AVATAR_MAX_FAILS) {
            guint delay = rand() / RAND_MAX * MRIM_AVATAR_DELAY;
            purple_timeout_add(delay, _mrim_fetch_avatar_delayed, ar); 
        }
    }
}

static void
_mrim_fetch_avatar(MrimData *md, const gchar *email)
{
    gchar* box = g_strdup(email);
    gchar* at  = g_strstr_len(box, -1, "@");
    gchar* dot = g_strstr_len(at, -1, ".");
    if (!at || !dot) {
        purple_debug_warning("mrim", "failed to parse email %s", email);
        return;
    }
    gchar* domain = at + 1;
    *at = *dot = '\0';

    MrimAvatarRequest *ar = g_new0(MrimAvatarRequest, 1);
    ar->md = md;
    ar->email = g_strdup(email);
    ar->url = g_strconcat("http://obraz.foto.mail.ru/", domain, "/", box, "/_mrimavatarsmall", NULL);
    g_free(box);

    purple_debug_info("mrim", "fetching avatar from %s\n", ar->url);
    purple_util_fetch_url(ar->url, TRUE, NULL, TRUE, _mrim_fetch_avatar_cb, ar);
}

/**************************************************/
/************* CONTACT MANIPULATION ***************/
/**************************************************/

/**
 * Should arrange for purple_notify_userinfo() to be called with
 * who's user info.
 */

void 
mrim_get_info(PurpleConnection *gc, const gchar *who)
{
    MrimData *md = (MrimData*) gc->proto_data;
    MrimAttempt *atmp = NULL;
    gchar **nick_n_domain = g_strsplit(who, "@", 2);
    mrim_pkt_build_wp_request(md, 2, MRIM_CS_WP_REQUEST_PARAM_USER, nick_n_domain[0],
                                     MRIM_CS_WP_REQUEST_PARAM_DOMAIN, nick_n_domain[1]);
    _send_out(md);
    g_strfreev(nick_n_domain);

    atmp = _mrim_attempt_new(ATMP_CONTACT_INFO, who);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} sending user info request for '%s'\n", (guint) md->tx_seq, who);
}

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
_mrim_add_contact(MrimData *md, const gchar *email, const gchar *group_nick)
{
    PurpleBuddy *buddy = NULL;
    MrimContact *contact = NULL;
    MrimAttempt *atmp = NULL;
    MrimGroup *group = NULL;

    if (g_hash_table_lookup_extended(md->contacts, email, NULL, (gpointer*) &contact)) {
        purple_debug_info("mrim", "_mrim_add_contact: user %s already exists. " \
                                    "Requsting authorization\n",  email);
        _mrim_request_authorization_dialog(md, email);
        return;
    }

    if (!g_hash_table_lookup_extended(md->groups, group_nick, NULL, (gpointer*) &group)) {
        _mrim_add_group(md, group_nick, email, NULL);
        return;
    }
    if (!(buddy = purple_find_buddy(md->account, email))) {
        purple_debug_error("mrim", "_mrim_add_contact: failed to find buddy for %s\n", email);
        return;
    }
    
    contact = mrim_contact_new(0, 0, CONTACT_INTFLAG_NOT_AUTHORIZED, STATUS_OFFLINE, group->id,
                                mrim_normalize(md->account, purple_buddy_get_name(buddy)),
                                purple_buddy_get_alias(buddy));
    
    atmp = _mrim_attempt_new(ATMP_ADD_CONTACT, contact);

    mrim_pkt_build_add_contact(md, 0, group->id, contact->email, contact->nick);
    _send_out(md);
    
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} adding user %s to group %s (%u)\n", (guint) md->tx_seq, 
                                    contact->email, group->nick, (guint) group->id);
}

void 
mrim_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    MrimData *md = (MrimData*) gc->proto_data;
    _mrim_add_contact(md, mrim_normalize(md->account, purple_buddy_get_name(buddy)),
                            purple_group_get_name(group));
}

static void
_mrim_remove_buddy(MrimData *md, const gchar* email)
{
    MrimContact *contact = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, email, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "remove buddy: failed to find mrim contact for %s\n", email);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags | CONTACT_FLAG_REMOVED, 
                                    contact->group_id, contact->email, contact->nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_REMOVE_CONTACT, contact);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} removing user %s\n", (guint) md->tx_seq, contact->email);
}

void 
mrim_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
    _mrim_remove_buddy((MrimData*) gc->proto_data, purple_buddy_get_name(buddy));
}

static void
_mrim_alias_buddy(MrimData *md, const gchar *email, const gchar *old_nick, const gchar *new_nick)
{
    MrimContact *contact = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, email, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "renaming buddy: failed to find mrim user for %s\n", email);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags, contact->group_id, contact->email, new_nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_RENAME_CONTACT, contact, new_nick);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} renaming user %s (%u) to %s\n", (guint) md->tx_seq, 
                                contact->email, contact->id, new_nick);
}

void 
mrim_alias_buddy(PurpleConnection *gc, const char *who, const char *alias)
{
    _mrim_alias_buddy((MrimData*) gc->proto_data, who, NULL, alias);
}

static void
_mrim_group_buddy(MrimData *md, const gchar *email, const gchar *old_group, const gchar *new_group)
{
    MrimContact *contact = NULL;
    MrimGroup *group = NULL;
    MrimAttempt *atmp = NULL;

    if (!g_hash_table_lookup_extended(md->contacts, email, NULL, (gpointer*) &contact)) {
        purple_debug_error("mrim", "group_buddy: failed to find mrim contact for %s\n", email);
        return;
    }
    if (!g_hash_table_lookup_extended(md->groups, new_group, NULL, (gpointer*) &group)) {
        _mrim_add_group(md, new_group, NULL, email);
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags, group->id, contact->email, contact->nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_MOVE_CONTACT, contact, group);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} moving user %s to group %s (%u)\n", (guint) md->tx_seq, 
                                contact->email, group->nick, (guint) group->id);
}

void 
mrim_group_buddy(PurpleConnection *gc, const gchar *email, 
                                        const gchar *old_group, const gchar *new_group)
{
    _mrim_group_buddy((MrimData*) gc->proto_data, email, old_group, new_group);
}

/**************************************************/
/************* CHAT *******************************/
/**************************************************/

static PurpleConversation*
_mrim_chat_join(MrimData *md, gchar *email)
{
    PurpleChat *chat = NULL;
    PurpleConversation *conv = NULL;

    if (!is_chat_email(email)) {
        purple_debug_error("mrim", "_mrim_chat_join: attempt to join with bad email: '%s'\n", email);
        return;
    }
    purple_debug_info("mrim", "_mrim_chat_join: loading memebers for chat %s\n", email);
    chat = mrim_find_blist_chat(md->account, email);
    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, 
                               purple_chat_get_name(chat), md->account);

    if (!conv || purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv))) {
        conv = serv_got_joined_chat(purple_account_get_connection(md->account),
                                chat_email2id(email), purple_chat_get_name(chat));
    }
    mrim_pkt_build_chat_get_members(md, 0, email);
    _send_out(md);
    
    return conv;
}

void
mrim_chat_join(PurpleConnection *gc, GHashTable *components)
{
    MrimData *md = (MrimData*) gc->proto_data;
    PurpleChat *chat = NULL;
    gchar *email = g_hash_table_lookup(components, "email");

    if (is_chat_email(email)) {
        // chat already exists or at least email is known. just join
        _mrim_chat_join(md, email);
        return;
    }

    // chat is not even exist. create new chat
    email = g_malloc0(MRIM_EMAIL_BUF_LEN);
    g_snprintf(email, MRIM_EMAIL_BUF_LEN, "%d@temporary", rand());
    purple_debug_info("mrim", "mrim_chat_join: creating new chat. temp email is %s\n", email);
    // here is hack to find chat with empty components: we have a pointer components
    // hash, so let's populate it with email and find chat by name!
    g_hash_table_replace(components, g_strdup("email"), email);
    chat = mrim_find_blist_chat(md->account, email);
    mrim_pkt_build_add_chat(md, CONTACT_FLAG_MULTICHAT, purple_chat_get_name(chat), FALSE);
    _send_out(md);
    MrimAttempt *atmp = _mrim_attempt_new(ATMP_CREATE_CHAT, email);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);
}

void
mrim_chat_leave(PurpleConnection *gc, gint id)
{
    // do nothing
    purple_debug_info("mrim", "mrim_chat_leave: %s\n", chat_id2email(id));
}

static void
_mrim_chat_removed_cb(PurpleBlistNode *node, gpointer ptr)
{
    MrimData* md = (MrimData*) ptr;
    PurpleBlistNodeType type = purple_blist_node_get_type(node);
    PurpleChat *chat;
    MrimAttempt *atmp = NULL;
    MrimContact *contact = NULL;
    
    if (type != PURPLE_BLIST_CHAT_NODE) {
        return;
    }

    chat = PURPLE_CHAT(node);
    contact = _mrim_contact_from_chat(chat);
    if (!contact) {
        purple_debug_error("mrim", "_mrim_chat_removed_cb: failed to find mrim contact for chat %s\n", 
                            purple_chat_get_name(chat));
        return;
    }

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags | CONTACT_FLAG_REMOVED, 
                                    contact->group_id, contact->email, contact->nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_REMOVE_CHAT, contact);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);

    purple_debug_info("mrim", "{%u} removing chat %s\n", (guint) md->tx_seq, contact->email);
}

static void
_mrim_chat_aliased_cb(PurpleBlistNode *node, gchar *old_nick, gpointer ptr)
{
    MrimData* md = (MrimData*) ptr;
    PurpleBlistNodeType type = purple_blist_node_get_type(node);
    PurpleChat *chat;
    MrimAttempt *atmp = NULL;
    MrimContact *contact = NULL;
    gchar *new_nick = NULL;
    
    if (type != PURPLE_BLIST_CHAT_NODE) {
        return;
    }

    chat = PURPLE_CHAT(node);
    new_nick = purple_chat_get_name(chat);
    contact = _mrim_contact_from_chat(chat);
    if (!contact) {
        purple_debug_error("mrim", "_mrim_chat_aliased_cb buddy: failed to find contact for chat %s\n", new_nick);
        return;
    }

    purple_debug_info("mrim", "{%u} renaming chat %s (%u) to %s\n", (guint) md->tx_seq, 
                                contact->email, contact->id, new_nick);

    mrim_pkt_build_modify_contact(md, contact->id, contact->flags, contact->group_id, contact->email, new_nick);
    _send_out(md);

    atmp = _mrim_attempt_new(ATMP_RENAME_CHAT, contact, new_nick);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);
}

void 
mrim_chat_invite(PurpleConnection *gc, gint id, const gchar *message, const gchar *who)
{
    MrimData *md = (MrimData*) gc->proto_data;
    MrimAttempt *atmp = NULL;
    gchar *email = chat_id2email(id);
    if (!g_hash_table_lookup(md->contacts, who)) {
        purple_debug_error("mrim", "mrim_chat_invite: can't find recepient %s in contact list\n", who);
        return;
    }
    purple_debug_info("mrim", "mrim_chat_invite: sending invitation to %s into the chat %s\n", who, email);
    mrim_pkt_build_chat_invite(md, 0, email, who, message);
    atmp = _mrim_attempt_new(ATMP_INVITE_USER, email, who);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);
}

int 
mrim_chat_send(PurpleConnection *gc, gint id, const gchar *message, PurpleMessageFlags flags)
{
    MrimData *md = (MrimData*) gc->proto_data;
    return _mrim_send_message(md, chat_id2email(id), message, 0);
}

/**************************************************/
/************* DISPATCH ***************************/
/**************************************************/

static void
_dispatch_chat_message_ack(MrimData *md, guint32 flags, gchar *from, gchar *message)
{
    PurpleConnection *gc = purple_account_get_connection(md->account);
    PurpleConversation *conv = NULL;
    MrimAuthParams *auth_params = NULL;
    PurpleChat *chat = NULL;
    gchar *clean = NULL, *who_part = NULL, *msg_part = NULL, *delim = NULL;

    purple_debug_info("mrim", "chat message from %s flags 0x%08x\n == \n%s\n == \n", from, (guint) flags, message);

    clean = purple_markup_escape_text(message, -1);
    if (delim = g_strstr_len(clean, -1, ":\r\n")) {
        *delim = '\0';
        who_part = clean;
        msg_part = delim + 3;
    }
    else {
        who_part = from;
        msg_part = clean;
    }

    if (flags & MESSAGE_FLAG_NOTIFY) {
        // chats does not support typing, just ignore
    }
    else if (!g_hash_table_lookup(md->contacts, from)) {
        // incoming message, while chat is not exist
        // we were invited to new chat.
        mrim_pkt_build_chat_get_members(md, 0, from);
        _send_out(md);
        MrimAttempt *atmp = _mrim_attempt_new(ATMP_ACCEPT_CHAT1);
        // HACK: chat_members packet is not an reply to get_members, 
        // so we can't use tx_seq as attemp number.
        // But we can use chat id - it will work in most cases.
        g_hash_table_insert(md->attempts, (gpointer) (BIG_NUM + chat_email2id(from)), atmp);
    }
    else {
        conv = _mrim_chat_join(md, from);
        purple_conv_chat_write(PURPLE_CONV_CHAT(conv), who_part, msg_part, PURPLE_MESSAGE_RECV, time(NULL));
    }

    g_free(clean);
}

static void
_mrim_accept_chat(MrimData *md, gchar *email, gchar *nick)
{
    GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_replace(components, g_strdup("email"), g_strdup(email));
    PurpleChat *chat = purple_chat_new(md->account, nick, components);
    purple_blist_add_chat(chat, NULL, NULL);
    mrim_pkt_build_add_contact(md, CONTACT_FLAG_MULTICHAT, 0, email, nick);
    _send_out(md);
    MrimAttempt *atmp = _mrim_attempt_new(ATMP_ACCEPT_CHAT2, email, nick);
    g_hash_table_insert(md->attempts, (gpointer) md->tx_seq, atmp);
}

static void
_chat_dispatch_members(MrimData *md, MrimPktMessageAck *pkt, MrimPktChatMembers *chat_pkt)
{
    GList *item = NULL;
    PurpleChat *chat = NULL;
    PurpleConversation *conv = NULL;
    PurpleConvChat *conv_chat = NULL;
    MrimAttempt *atmp = NULL;
    gchar *email = NULL;

    // special case: receiving chat members before accepting chat (just for nick)
    // HACK: chat_members packet is not an reply to get_members, 
    // so we can't use tx_seq as attemp number.
    // But we can use chat id - it will work in most cases.
    gpointer atmp_id = (gpointer) (BIG_NUM + chat_email2id(pkt->from));
    if (atmp = g_hash_table_lookup(md->attempts, atmp_id)) {
        if (atmp->type == ATMP_ACCEPT_CHAT1) {
            _mrim_accept_chat(md, pkt->from, chat_pkt->nick);
            g_hash_table_remove(md->attempts, atmp_id);
            return;
        }
        else {
            purple_debug_warning("mrim", "_chat_dispatch_members: unexpected attempt %u\n", atmp->type);
            g_hash_table_remove(md->attempts, atmp_id);
        }
    }

    if (!(chat = mrim_find_blist_chat(md->account, pkt->from))) {
        purple_debug_error("mrim", "_chat_dispatch_members: no blist chat for email %s\n", pkt->from);
        return;
    }

    if (!(conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, 
                                        purple_chat_get_name(chat), md->account)))
    {
        purple_debug_warning("mrim", "_chat_dispatch_members: no conversation for email %s\n", pkt->from);
        return;
    }
    conv_chat = PURPLE_CONV_CHAT(conv);

    // add new members to the chat
    for (item = chat_pkt->members; item; item = g_list_next(item)) {
        email = item->data;
        if (!purple_conv_chat_find_user(conv_chat, email)) {
            purple_conv_chat_add_user(conv_chat, email, NULL, 0, FALSE);
        }
    }

    // remove old members from the chat
    for (item = purple_conv_chat_get_users(conv_chat); item; item = g_list_next(item)) {
        email = (gchar*) purple_conv_chat_cb_get_name((PurpleConvChatBuddy*) item->data);
        if (!g_list_find_custom(chat_pkt->members, email, (GCompareFunc) g_strcmp0)) {
            purple_conv_chat_remove_user(conv_chat, email, NULL);
        }
    }

}

static void
_chat_dispatch(MrimData *md, MrimPktMessageAck *pkt)
{
    if (pkt->multichat) {
        // TODO: from here
        switch(pkt->multichat->type) {
            case MULTICHAT_MESSAGE:
                fprintf(stderr, "MULTICHAT_MESSAGE\n");
                break;
            case MULTICHAT_MEMBERS:
                _chat_dispatch_members(md, pkt, (MrimPktChatMembers*) pkt->multichat);
                break;
            case MULTICHAT_ADD_MEMBERS:
                fprintf(stderr, "MULTICHAT_ADD_MEMBERS\n");
                break;
            case MULTICHAT_ATTACHED:
                fprintf(stderr, "MULTICHAT_ATTACHED\n");
                break;
            case MULTICHAT_DETACHED:
                fprintf(stderr, "MULTICHAT_DETACHED\n");
                break;
            default:
                break;
        }
    }
    else {
        _dispatch_chat_message_ack(md, pkt->flags, pkt->from, pkt->message);
    }
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
_dispatch_normal_message_ack(MrimData *md, guint32 flags, gchar *from, gchar *message)
{
    PurpleConversation *conv = NULL;
    MrimContact *contact = NULL;
    MrimAuthParams *auth_params = NULL;
    gchar *clean = NULL;

    purple_debug_info("mrim", "message from %s flags 0x%08x\n", from, (guint) flags);

    if (flags & MESSAGE_FLAG_NOTIFY) {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, md->account);
        if (!conv) {
            return;
        }
        purple_conv_im_set_typing_state(PURPLE_CONV_IM(conv), PURPLE_TYPING);
        purple_conv_im_start_typing_timeout(PURPLE_CONV_IM(conv), MRIM_TYPING_TIMEOUT);
    }
    else if (flags & MESSAGE_FLAG_AUTHORIZE) {
        if (!g_hash_table_lookup_extended(md->contacts, from, NULL, (gpointer*) &contact)) {
            contact = NULL;
        }
        auth_params = _mrim_auth_params_new(md, from);
        purple_account_request_authorization(md->account, from, NULL, contact ? contact->nick : NULL, 
                    message, contact ? TRUE : FALSE, _mrim_authorize_cb, NULL, auth_params);
    }
    else {
        conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, from, md->account);
        if (!conv) {
            conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, md->account, from);
        }
        purple_conversation_set_name(conv, from);
        clean = purple_markup_escape_text(message, -1);
        purple_conv_im_write(PURPLE_CONV_IM(conv), from, clean, PURPLE_MESSAGE_RECV, time(NULL));
        g_free(clean);
    }
}

static void
_dispatch_message_ack(MrimData *md, MrimPktMessageAck *pkt)
{
    if (is_chat_email(pkt->from)) {
        _chat_dispatch(md, pkt);
    }
    else {
        _dispatch_normal_message_ack(md, pkt->flags, pkt->from, pkt->message);
    }
    if (!(pkt->flags & MESSAGE_FLAG_NORECV)) {
        mrim_pkt_build_message_recv(md, pkt->from, pkt->msg_id);
        _send_out(md);
    }
}

static const gchar*
_message_delivery_reason(guint32 status)
{
    switch (status) {
        case MESSAGE_DELIVERED:
            return "Message delivered";
            break;
        case MESSAGE_REJECTED_INTERR:
            return "Internal error";
            break;
        case MESSAGE_REJECTED_NOUSER:
            return "No such user";
            break;
        case MESSAGE_REJECTED_LIMIT_EXCEEDED:
            return "Offline message limit exceeded";
            break;
        case MESSAGE_REJECTED_TOO_LARGE:
            return "Message is too large";
            break;
        case MESSAGE_REJECTED_DENY_OFFMSG:
            return "User disabled offline messages";
            break;
        default:
            return "Unknown error";
            break;
    }
}

static void
_dispatch_message_status(MrimData *md, MrimPktMessageStatus *pkt)
{
    MrimAttempt *atmp = NULL;
    PurpleConversation *conv = NULL;
    PurpleChat *chat = NULL;
    const gchar* reason = _message_delivery_reason(pkt->status);
    const guint32 noecho_flags = (MESSAGE_FLAG_CONTACT|MESSAGE_FLAG_NOTIFY|MESSAGE_FLAG_AUTHORIZE);

    if (!(atmp = g_hash_table_lookup(md->attempts, (gpointer) pkt->header.seq))) {
        purple_debug_error("mrim", "_dispatch_message_status: no attempt for message seq %u\n",
                                        pkt->header.seq);
        return;
    }

    if (pkt->status == MESSAGE_DELIVERED) {
        if (atmp->type == ATMP_INVITE_USER) {
            purple_debug_info("mrim", "_dispatch_message_status: invite user %s to chat %s\n",
                                        atmp->invite_user.who, atmp->invite_user.email);
            conv = _mrim_chat_join(md, atmp->invite_user.email);
            purple_conv_chat_add_user(PURPLE_CONV_CHAT(conv), atmp->invite_user.who, NULL, 0, FALSE);
        }
        else if (atmp->type == ATMP_MESSAGE) {
            if (!(atmp->message.flags & noecho_flags)) {
                if (is_chat_email(atmp->message.email)) {
                    conv = _mrim_chat_join(md, atmp->message.email);
                    purple_conv_chat_write(PURPLE_CONV_CHAT(conv), atmp->message.email, 
                                            atmp->message.message, PURPLE_MESSAGE_SEND, time(NULL));
                }
                else {
                    conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, 
                                            atmp->message.email, md->account);
                    if (!conv) {
                        conv =  purple_conversation_new(PURPLE_CONV_TYPE_IM, md->account, atmp->message.email);
                    }
                    purple_conv_im_write(PURPLE_CONV_IM(conv), atmp->message.email, 
                                            atmp->message.message, PURPLE_MESSAGE_SEND, time(NULL));
                }
            }
        }
        else {
            purple_debug_error("mrim", "_dispatch_message_status: incorrect attempt type %u\n",
                                            atmp->type);
        }
    }
    else {
        purple_notify_error(md->account->gc, "Sending message", 
                                    "Failed to send message", reason);
    }

    g_hash_table_remove(md->attempts, (gpointer) pkt->header.seq);
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
            g_hash_table_replace(md->groups, group->nick, group);
            if (atmp->add_group.buddy_to_add) {
                _mrim_add_contact(md, atmp->add_group.buddy_to_add, group->nick);
            }
            else if (atmp->add_group.buddy_to_move) {
                _mrim_group_buddy(md, atmp->add_group.buddy_to_move, NULL, group->nick);
            }
        }
        else if (pkt->status == CONTACT_OPER_USER_EXISTS) {
            purple_debug_info("mrim", "group already existed\n");
            _mrim_group_destroy(group);
        }
        else {
            purple_notify_error(md->account->gc, "Adding group", 
                                        "Failed to create group on server", reason);
            purple_blist_remove_group(purple_find_group(group->nick));
            _mrim_group_destroy(group);
        }
    }

    else if (atmp->type == ATMP_ADD_CONTACT) {
        contact = atmp->add_contact.contact;
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            contact->id = pkt->contact_id;
            g_hash_table_replace(md->contacts, contact->email, contact);
            _mrim_fetch_avatar(md, contact->email);
        }
        else if (pkt->status == CONTACT_OPER_USER_EXISTS) {
            purple_debug_info("mrim", "user already %s existed\n", contact->email);
            _mrim_contact_destroy(contact);
        }
        else {
            purple_notify_error(md->account->gc, "Adding user", 
                                        "Failed to create user on server", reason);
            purple_blist_remove_buddy(purple_find_buddy(md->account, contact->email));
            _mrim_contact_destroy(contact);
        }
    }

    else if (atmp->type == ATMP_CREATE_CHAT) {
        PurpleChat *chat = mrim_find_blist_chat(md->account, atmp->create_chat.email);
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            contact = mrim_contact_new(pkt->contact_id, 0, CONTACT_FLAG_MULTICHAT, STATUS_ONLINE, 0,
                                       mrim_normalize(md->account, pkt->contact_email), 
                                       purple_chat_get_name(chat));
            g_hash_table_replace(md->contacts, contact->email, contact);
            GHashTable *components = purple_chat_get_components(chat);
            g_hash_table_replace(components, g_strdup("email"), g_strdup(contact->email));
            _mrim_chat_join(md, contact->email);
        }
        else {
            purple_notify_error(md->account->gc, "Creating chat", 
                                        "Failed to create chat contact on server", reason);
            purple_blist_remove_chat(chat);
        }
    }

    else if (atmp->type == ATMP_ACCEPT_CHAT2) {
        PurpleChat *chat = mrim_find_blist_chat(md->account, atmp->accept_chat2.email);
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            contact = mrim_contact_new(pkt->contact_id, 0, CONTACT_FLAG_MULTICHAT, STATUS_ONLINE, 0,
                                       mrim_normalize(md->account, atmp->accept_chat2.email), 
                                       atmp->accept_chat2.nick);
            g_hash_table_replace(md->contacts, contact->email, contact);
            _mrim_chat_join(md, contact->email);
        }
        else {
            purple_notify_error(md->account->gc, "Creating chat", 
                                        "Failed to create chat contact on server", reason);
            purple_blist_remove_chat(chat);
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

    if (!atmp) {
        purple_debug_warning("mrim", "failed to find attempt for seq %u\n", (guint) pkt->header.seq);
        return;
    }

    if (atmp->type == ATMP_REMOVE_GROUP) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_remove(md->groups, atmp->remove_group.group->nick);
        }
        else {
            purple_notify_error(md->account->gc, "Removing group", 
                                        "Failed to remove group on server", reason);
        }
    }

    else if (atmp->type == ATMP_RENAME_GROUP) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            _mrim_group_rename(md, atmp->rename_group.group, atmp->rename_group.new_nick);
        }
        else {
            purple_notify_error(md->account->gc, "Modifing group",
                                        "Failed to modify group on server", reason);
            /* HOWTO rename group back ? */
        }
    }

    else if (atmp->type == ATMP_REMOVE_CONTACT) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_remove(md->contacts, atmp->remove_contact.contact->email);
        }
        else {
            purple_notify_error(md->account->gc, "Removing user", 
                                        "Failed to remove user on server", reason);
            /* HOWTO undo deletion ? */
        }
    }
    
    else if (atmp->type == ATMP_MOVE_CONTACT) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            atmp->move_contact.contact->group_id = atmp->move_contact.group->id;
        }
        else {
            purple_notify_error(md->account->gc, "Moving user",
                                        "Failed to move user on server", reason);
        }
    }

    else if (atmp->type == ATMP_RENAME_CONTACT) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            _mrim_contact_set_nick(atmp->rename_contact.contact, atmp->rename_contact.new_nick);
        }
        else {
            purple_notify_error(md->account->gc, "Renaming user",
                                        "Failed to rename user on server", reason);
        }
    }

    else if (atmp->type == ATMP_REMOVE_CHAT) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            g_hash_table_remove(md->contacts, atmp->remove_chat.contact->email);
        }
        else {
            purple_notify_error(md->account->gc, "Leaving chat",
                                        "Failed to remove chat on server", reason);
            /* HOWTO undo deletion ? */
        }
    }

    else if (atmp->type == ATMP_RENAME_CHAT) {
        if (pkt->status == CONTACT_OPER_SUCCESS) {
            _mrim_contact_set_nick(atmp->rename_contact.contact, atmp->rename_contact.new_nick);
        }
        else {
            purple_notify_error(md->account->gc, "Renaming chat",
                                        "Failed to rename chat on server", reason);
            /* HOWTO undo renaming ? */
        }
    }

    else {
        purple_debug_warning("mrim", "unexpected type of attempt for seq %u\n", 
                                    (guint) pkt->header.seq);
    }

    g_hash_table_remove(md->attempts, (gpointer) pkt->header.seq);
}

static void
_dispatch_offline_message_ack(MrimData *md, MrimPktOfflineMessageAck* pkt)
{
    if (is_chat_email(pkt->from)) {
        // TODO: does chats supports offline messages ?
        _dispatch_chat_message_ack(md, pkt->flags, pkt->from, pkt->message);
    }
    else {
        _dispatch_normal_message_ack(md, pkt->flags, pkt->from, pkt->message);
    }

    /* offline messages should be accepted despite NORECV flag */
    mrim_pkt_build_offline_message_del(md, pkt->uidl);
    _send_out(md);
}

static void
_dispatch_authorize_ack(MrimData *md, MrimPktAuthorizeAck *pkt)
{
    MrimContact *contact = NULL;
    gchar *msg = NULL;

    if (g_hash_table_lookup_extended(md->contacts, pkt->email, NULL, (gpointer*) &contact)) {
        contact->server_flags &= !CONTACT_INTFLAG_NOT_AUTHORIZED;
        purple_debug_info("mrim", "_dispatch_authorize_ack: you were authorized by %s\n", contact->email);
        if (!is_chat_email(contact->email)) {
            msg = g_strdup_printf("You were authorized by %s", contact->email);
            purple_notify_info(md->account->gc, "Authorization", msg, NULL);
            g_free(msg);
        }
    }
    else {
        purple_debug_warning("mrim", "_dispatch_authorize_ack", "User %s was not found\n", pkt->email);
    }
}

static void
_dispatch_user_status(MrimData *md, MrimPktUserStatus *pkt)
{
    purple_debug_info("mrim", "contact status changed %s to 0x%08x\n",
                        pkt->email, (guint) pkt->status);

    MrimContact *contact = NULL;
    if (g_hash_table_lookup_extended(md->contacts, pkt->email, NULL, (gpointer*) &contact)) {
        contact->status = pkt->status;
        purple_prpl_got_user_status(md->account, pkt->email, 
                            _status_mrim2purple(pkt->status), NULL);
    }
    else {
        purple_debug_warning("mrim", "_dispatch_user_status: failed to find contact for email %s\n", pkt->email);
    }
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
_dispatch_contact_info(MrimData *md, gchar *email, MrimPktAnketaInfo *pkt)
{
    GHashTable *user = NULL;
    gchar *key = NULL, *val = NULL;
    PurpleNotifyUserInfo *user_info = purple_notify_user_info_new();

    if (pkt->status == MRIM_ANKETA_INFO_STATUS_OK && pkt->users) {

        purple_notify_user_info_add_pair(user_info, "E-mail", email);
        gchar **nd = g_strsplit(email, "@", 2);
        gchar **parts = g_strsplit(nd[1], ".", 2);
        gchar *myworld_url = g_strdup_printf("http://my.mail.ru/%s/%s/", parts[0], nd[0]);
        gchar *blog_url =  g_strdup_printf("http://blogs.mail.ru/%s/%s/", parts[0], nd[0]);
        purple_notify_user_info_add_pair(user_info, "MyWorld", myworld_url);
        purple_notify_user_info_add_pair(user_info, "Blog", blog_url);
        g_free(blog_url);
        g_free(myworld_url);
        g_strfreev(parts);
        g_strfreev(nd);

        user = (GHashTable*) pkt->users->data;
        if ((val = g_hash_table_lookup(user, "Nickname")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "Nick", val);
        }
        if ((val = g_hash_table_lookup(user, "FirstName")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "First Name", val);
        }
        if ((val = g_hash_table_lookup(user, "LastName")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "Last Name", val);
        }
        if ((val = g_hash_table_lookup(user, "Sex")) && strlen(val)) {
            const gchar *sex = atol(val) == 1 ? "Male" : 
                               atol(val) == 2 ? "Female" :
                               "Unknown";
            purple_notify_user_info_add_pair(user_info, "Sex", sex);
        }
        if ((val = g_hash_table_lookup(user, "Birthday")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "Birthday", val);
        }
        if ((val = g_hash_table_lookup(user, "Phone")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "Phone", val);
        }
        if ((val = g_hash_table_lookup(user, "Zodiac")) && strlen(val)) {
            const gchar* zodiac[] = {
                "The Ram", "The Bull", "The Twins", "The Crab", 
                "The Lion", "The Virgin", "The Scales", "The Scorpion", 
                "The Archer", "The Sea-Goat", "The Water Bearer", "The Fish"
            };
            guint32 idx = (guint32) atoi(val);
            if (idx > 0 && idx < sizeof(zodiac) / sizeof(gchar*) + 1) {
                purple_notify_user_info_add_pair(user_info, "Zodiac", zodiac[idx - 1]);
            }
        }
        if ((val = g_hash_table_lookup(user, "Location")) && strlen(val)) {
            purple_notify_user_info_add_pair(user_info, "Location", val);
        }
    }
    else {
        purple_notify_user_info_add_pair(user_info, NULL, "Failed to load contact info");
        purple_debug_error("mrim", "Failed to load contact info for %s\n", email);
    }
    
    purple_notify_userinfo(md->account->gc, email, user_info, NULL, NULL);
    purple_notify_user_info_destroy(user_info);
}

static void
_dispatch_search_results(MrimData *md, MrimPktAnketaInfo *pkt)
{
}

static void
_dispatch_anketa_info(MrimData *md, MrimPktAnketaInfo* pkt)
{
    purple_debug_info("mrim", "anketa info dispatch %d\n", (guint) pkt->header.seq);
 
    MrimAttempt *atmp;

    if (g_hash_table_lookup_extended(md->attempts, (gpointer) pkt->header.seq, NULL, (gpointer*) &atmp)) {
        if (atmp->type == ATMP_CONTACT_INFO) {
            _dispatch_contact_info(md, atmp->contact_info.email, pkt);
        }
        else if (atmp->type == ATMP_CONTACT_SEARCH) {
            _dispatch_search_results(md, pkt);
        }
        else {
            purple_debug_error("mrim", "incorrect attempt type for anketa info request\n");
        }
    }
    else {
        purple_debug_error("mrim", "failed to find attempt for anketa info request\n");
    }
}

static void
_dispatch_contact_list(MrimData *md, MrimPktContactList *pkt)
{
    MrimGroup *mgroup = NULL;
    MrimContact *contact = NULL;
    PurpleGroup *group = NULL;
    PurpleBuddy *buddy = NULL;
    PurpleChat *chat = NULL;
    GList *item = NULL;

    /* clean d-bus handlers */
    static int dbus_handle;
    purple_signals_disconnect_by_handle(&dbus_handle);

    if (pkt->status != GET_CONTACTS_OK) {
        purple_connection_error_reason(md->account->gc,
            PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
            "Failed to load contact list"
        );
        return;
    }
 
    g_hash_table_remove_all(md->groups);
    g_hash_table_remove_all(md->contacts);

    /* add groups */
    for (item = g_list_first(pkt->groups); item; item = g_list_next(item)) {
        mgroup = (MrimGroup*) item->data;
        if (!(mgroup->flags & CONTACT_FLAG_REMOVED)) {
            if (!(group = purple_find_group(mgroup->nick))) {
                group = purple_group_new(mgroup->nick);
                purple_blist_add_group(group, NULL);
            }
            g_hash_table_replace(md->groups, mgroup->nick, mgroup);
            purple_debug_info("mrim", "contact_list: group: [%u] %s [flags: %u]\n", 
                                        mgroup->id, mgroup->nick, mgroup->flags);
        }
        else {
            purple_debug_misc("mrim", "contact_list: group: [%u] %s [removed]\n", mgroup->id, mgroup->nick);
        }
    }

    /* add contacts and chats */
    for (item = g_list_first(pkt->contacts); item; item = g_list_next(item)) {
        contact = (MrimContact*) item->data;
        if (!(contact->flags & CONTACT_FLAG_REMOVED)) {
            mgroup = _mrim_contact_get_group(md, contact);
            if (mgroup && !(mgroup->flags & CONTACT_FLAG_REMOVED)) {
                group = purple_find_group(mgroup->nick);
            }
            else {
                group = NULL;
            }
            g_hash_table_replace(md->contacts, contact->email, contact);
            if (is_chat_email(contact->email)) {
                if (chat = mrim_find_blist_chat(md->account, contact->email)) {
                    purple_blist_alias_chat(chat, contact->nick);
                }
                else {
                    GHashTable *components = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
                    g_hash_table_replace(components, g_strdup("email"), g_strdup(contact->email));
                    chat = purple_chat_new(md->account, contact->nick, components);
                }
                // agent holds all chats in one group "chats", so we do
                purple_blist_add_chat(chat, NULL, NULL);
            }
            else {
                // we preserve libpurple's contacts, but overwrites groups from server
                if (buddy = purple_find_buddy(md->account, contact->email)) {
                    purple_blist_alias_buddy(buddy, contact->nick);
                }
                else {
                    buddy = purple_buddy_new(md->account, contact->email, contact->nick);
                }
                // purple_blist_add_buddy will actually move exists buddy to proper place
                purple_blist_add_buddy(buddy, purple_buddy_get_contact(buddy), group, NULL);
                purple_prpl_got_user_status(md->account, contact->email, 
                                        _status_mrim2purple(contact->status), NULL);
            }
            purple_debug_info("mrim", "contact_list: %s: [%u] %s (%s) [group %u flags %u server flags %u]\n", 
                                       is_chat_email(contact->email) ? "chat" : "contact",
                                       contact->id, contact->email, contact->nick, contact->group_id, 
                                       contact->flags, contact->server_flags);
            _mrim_fetch_avatar(md, contact->email);
        }
        else {
            purple_debug_misc("mrim", "contact_list: %s: [%u] %s (%s) [removed]\n",
                                       is_chat_email(contact->email) ? "chat" : "contact",
                                       contact->id, contact->email, contact->nick);
        }
    }

    // remove deleted contacts and chats
    PurpleBlistNode *node, *group_node;

    for (group_node = purple_blist_get_root(); 
         group_node != NULL; 
         group_node = purple_blist_node_next(group_node, TRUE)) 
    {
        for (node = purple_blist_node_get_first_child(group_node);
             node != NULL; 
             node = purple_blist_node_next(node, TRUE)) 
        {
            if (PURPLE_BLIST_NODE_IS_CHAT(node)) {
                chat = (PurpleChat*) node;
                GHashTable *components = purple_chat_get_components(chat);
                gchar *email = g_hash_table_lookup(components, "email");
                if (md->account == purple_chat_get_account(chat) && email
                    && !g_hash_table_lookup(md->contacts, email))
                {
                    purple_blist_remove_chat(chat);
                }
            }
            if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
                buddy = (PurpleBuddy*) node;
                if (md->account == purple_buddy_get_account(buddy)
                    && !g_hash_table_lookup(md->contacts, purple_buddy_get_name(buddy)))
                {
                    purple_blist_remove_buddy(buddy);
                }
            }
        }
    }

    /* set d-bus handlers */
    purple_signal_connect(purple_blist_get_handle(), "blist-node-removed", &dbus_handle, 
            PURPLE_CALLBACK(_mrim_chat_removed_cb), md);
    purple_signal_connect(purple_blist_get_handle(), "blist-node-aliased", &dbus_handle, 
            PURPLE_CALLBACK(_mrim_chat_aliased_cb), md);
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
            _dispatch_offline_message_ack(md, (MrimPktOfflineMessageAck*) pkt);
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            _dispatch_authorize_ack(md, (MrimPktAuthorizeAck*) pkt);
            break;
        case MRIM_CS_MPOP_SESSION:
            break;
        case MRIM_CS_ANKETA_INFO:
            _dispatch_anketa_info(md, (MrimPktAnketaInfo*) pkt);
            break;
        case MRIM_CS_CONTACT_LIST2:
            _dispatch_contact_list(md, (MrimPktContactList*) pkt);
            break;
        default:
            break;
    }
}

/**************************************************/
/************* INFORMATION FUNCTIONS **************/
/**************************************************/

const char*
mrim_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
    return "mrim";
}

const char*
mrim_list_emblem(PurpleBuddy *buddy)
{
    MrimContact *contact = NULL;
    
    if (contact = _mrim_contact_from_buddy(buddy)) {
        if (contact->server_flags & CONTACT_INTFLAG_NOT_AUTHORIZED) {
            return "not-authorized";
        }
    }
    
    return NULL;
}

/*
 * Allows the prpl to add text to a buddy's tooltip.
 */
void 
mrim_tooltip_text (PurpleBuddy *buddy, PurpleNotifyUserInfo *nui, gboolean full)
{
}

GList*
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

GList*
mrim_blist_node_menu(PurpleBlistNode *node)
{
    GList *list = NULL;
    PurpleMenuAction *action = NULL;
    MrimData *md = NULL;
    MrimContact *contact = NULL;
    MrimAuthParams *params = NULL;

    if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
        if (contact = _mrim_contact_from_buddy(PURPLE_BUDDY(node))) {
            if (contact->server_flags & CONTACT_INTFLAG_NOT_AUTHORIZED) {
                md = _mrim_data_from_buddy(PURPLE_BUDDY(node));
                params = _mrim_auth_params_new(md, contact->email);
                action = purple_menu_action_new("Request authorization", 
                    G_CALLBACK(_mrim_request_authorization_menu_cb), params, NULL);
                list = g_list_append(list, action);
            }
        }
    }

    return list;
}

GList*
mrim_chat_info(PurpleConnection *gc)
{
    struct proto_chat_entry *entry = g_malloc0(sizeof(struct proto_chat_entry));
    entry->label = "E-mail";
    entry->identifier = "email";
    entry->required = 0;
    entry->is_int = 0;
    entry->secret = 0;
    return g_list_append(NULL, entry);
}

GHashTable*
mrim_chat_info_defaults(PurpleConnection *gc, const gchar *name)
{
    GHashTable *comps = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    g_hash_table_replace(comps, g_strdup("email"), g_strdup(""));
    return comps;
}

gboolean 
mrim_offline_message(const PurpleBuddy *buddy)
{
    return TRUE;
}

const char*
mrim_normalize(const PurpleAccount *account, const char *who)
{
    static gchar buf[MRIM_EMAIL_BUF_LEN];
    char *tmp = g_ascii_strdown(who, -1);
    g_strstrip(tmp);
    g_snprintf(buf, sizeof(buf), "%s", tmp);
    g_free(tmp);
    buf[MRIM_EMAIL_BUF_LEN - 1] = '\0';
    return buf;
}
