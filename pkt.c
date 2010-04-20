#include <glib.h>
#include <string.h>
#include "pkt.h"

/* Common utils */

#define PKT_LEN(pkt) (GUINT32_FROM_LE(pkt->dlen) + sizeof(MrimPktHeader))
#define LPS_LEN(lps) (GUINT32_FROM_LE((lps)->length) + sizeof((lps)->length))

typedef struct {
    guint32 length;
    gchar data[];
} MrimPktLps;

static MrimPktLps*
_str2lps(const gchar *str)
{
    gchar *data = NULL;
    guint32 data_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    MrimPktLps *lps = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);
    data = g_convert_with_fallback(str, strlen(str), "WINDOWS-1251", local_charset, "?", 
                            NULL, &data_len, &err);
    if (!data) {
        fprintf(stderr, "FAILED STR2LPS: bad encoding %s\n", err->message);
        return NULL;
    }

    lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + data_len);
    lps->length = GUINT32_TO_LE(data_len);
    memcpy(lps->data, data, data_len);
    g_free(data);
    return lps;
}

static gchar*
_lps2str(MrimPktLps *lps)
{
    gchar *str = NULL;
    guint32 str_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);
    str = g_convert_with_fallback(lps->data, lps->length, local_charset, "WINDOWS-1251", "?",
                            NULL, &str_len, &err);
    if (!str) {
        fprintf(stderr, "FAILED STR2LPS: bad encoding %s\n", err->message);
        return NULL;
    }

    return str;
}

/* Client to Server messages */

static void
_init_header(MrimPktHeader *header, guint32 seq, guint32 msg, guint32 dlen)
{
    header->magic = GUINT32_TO_LE(CS_MAGIC);
    header->proto = GUINT32_TO_LE(PROTO_VERSION);
    header->seq = GUINT32_TO_LE(seq);
    header->msg = GUINT32_TO_LE(msg);
    header->dlen = GUINT32_TO_LE(dlen);
    header->from = GUINT32_TO_LE(0x00000000);
    header->fromport = GUINT32_TO_LE(0x00000000);
    memset(header->reserved, '\0', 16);
}

void
mrim_pkt_build_hello(MrimData *md) 
{
    MrimPktHeader header;
    _init_header(&header, ++md->tx_seq, MRIM_CS_HELLO, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}

void
mrim_pkt_build_login(MrimData *md, const gchar *login, const gchar *pass,
                    guint32 status, const gchar *agent)
{
    MrimPktLps *lps_login = NULL, *lps_pass = NULL, *lps_agent = NULL;
    MrimPktHeader header;
    guint32 dlen = 0;

    if (!(lps_login = _str2lps(login))) {
        return;
    }
    if (!(lps_pass = _str2lps(pass))) {
        g_free(lps_login);
        return;
    }
    status = GUINT32_TO_LE(status);
    if (!(lps_agent = _str2lps(agent))) {
        g_free(lps_login);
        g_free(lps_pass);
        return;
    }

    dlen = LPS_LEN(lps_login) + LPS_LEN(lps_pass) +
            sizeof(dlen) + LPS_LEN(lps_agent);

    _init_header(&header, ++md->tx_seq, MRIM_CS_LOGIN2, dlen);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_login, LPS_LEN(lps_login));
    purple_circ_buffer_append(md->server.tx_buf, lps_pass, LPS_LEN(lps_pass));
    purple_circ_buffer_append(md->server.tx_buf, &status, sizeof(status));
    purple_circ_buffer_append(md->server.tx_buf, lps_agent, LPS_LEN(lps_agent));
    g_free(lps_login);
    g_free(lps_pass);
    g_free(lps_agent);

    return;
}

void
mrim_pkt_build_ping(MrimData *md)
{
    MrimPktHeader header;
    _init_header(&header, ++md->tx_seq, MRIM_CS_PING, 0);
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
}

void
mrim_pkt_build_change_status(MrimData *md, guint32 status)
{
    MrimPktHeader header;
    status = GUINT32_TO_LE(status);
    _init_header(&header, ++md->tx_seq, MRIM_CS_CHANGE_STATUS, sizeof(status));
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &status, sizeof(status));
}

void
mrim_pkt_build_add_contact(MrimData *md, guint32 flags, guint32 group_id, 
                    const gchar *email, const gchar *name)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL, *lps_name = NULL, *lps_unused = NULL;

    flags = GUINT32_TO_LE(flags);
    group_id = GUINT32_TO_LE(group_id);
    if (!(lps_email = _str2lps(email))) {
        return;
    }
    if (!(lps_name = _str2lps(name))) {
        g_free(lps_email);
        return;
    }
    if (!(lps_unused = _str2lps(" "))) {
        g_free(lps_name);
        g_free(lps_email);
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_ADD_CONTACT, 
        2 * sizeof(guint32) + LPS_LEN(lps_email) 
        + LPS_LEN(lps_name) + LPS_LEN(lps_unused));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, &group_id, sizeof(group_id));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));
    purple_circ_buffer_append(md->server.tx_buf, lps_name, LPS_LEN(lps_name));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));

    g_free(lps_email);
    g_free(lps_name);
    g_free(lps_unused);
}

void
mrim_pkt_build_modify_contact(MrimData *md, guint32 id, guint32 flags, guint32 group_id, 
                    const gchar *email, const gchar *name)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL, *lps_name = NULL, *lps_unused = NULL;

    id = GUINT32_TO_LE(id);
    flags = GUINT32_TO_LE(flags);
    group_id = GUINT32_TO_LE(group_id);
    if (!(lps_email = _str2lps(email))) {
        return;
    }
    if (!(lps_name = _str2lps(name))) {
        g_free(lps_email);
        return;
    }
    if (!(lps_unused = _str2lps(" "))) {
        g_free(lps_name);
        g_free(lps_email);
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_MODIFY_CONTACT, 
        3 * sizeof(guint32) + LPS_LEN(lps_email) 
        + LPS_LEN(lps_name) + LPS_LEN(lps_unused));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &id, sizeof(id));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, &group_id, sizeof(group_id));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));
    purple_circ_buffer_append(md->server.tx_buf, lps_name, LPS_LEN(lps_name));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));

    g_free(lps_email);
    g_free(lps_name);
    g_free(lps_unused);
}

void
mrim_pkt_build_message(MrimData *md, guint32 flags, gchar *to, gchar *message, gchar *rtf_message)
{
    MrimPktHeader header;
    MrimPktLps *lps_to = NULL, *lps_message = NULL, *lps_rtf_message = NULL;

    flags = GUINT32_TO_LE(flags);
    if (!(lps_to = _str2lps(to))) {
        return;
    }
    if (!(lps_message = _str2lps(message))) {
        g_free(lps_to);
        return;
    }
    if (!(lps_rtf_message = _str2lps(rtf_message))) {
        g_free(lps_to);
        g_free(lps_message);
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_MESSAGE, sizeof(flags) + LPS_LEN(lps_to)
        + LPS_LEN(lps_message) + LPS_LEN(lps_rtf_message));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, lps_to, LPS_LEN(lps_to));
    purple_circ_buffer_append(md->server.tx_buf, lps_message, LPS_LEN(lps_message));
    purple_circ_buffer_append(md->server.tx_buf, lps_rtf_message, LPS_LEN(lps_rtf_message));

    g_free(lps_to);
    g_free(lps_message);
    g_free(lps_rtf_message);
}

void
mrim_pkt_build_message_recv(MrimData *md, gchar *from, guint32 msg_id)
{
    MrimPktHeader header;
    MrimPktLps *lps_from = NULL;

    msg_id = GUINT32_TO_LE(msg_id);
    if (!(lps_from = _str2lps(from))) {
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_MESSAGE_RECV, sizeof(msg_id) + LPS_LEN(lps_from));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_from, LPS_LEN(lps_from));
    purple_circ_buffer_append(md->server.tx_buf, &msg_id, sizeof(msg_id));

    g_free(lps_from);
}

void
mrim_pkt_build_authorize(MrimData *md, gchar *email)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL;

    if (!(lps_email = _str2lps(email))) {
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_AUTHORIZE, LPS_LEN(lps_email));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));

    g_free(lps_email);
}

/* Server to Client messages */

/* Collect bytes in rx_pkt_buf for just one packet 
   Returns NULL if there are not sufficient bytes in circle buffer
*/

static MrimPktHeader*
_collect(MrimData *md)
{
    guint available = 0;
    gint need_read = 0;
    MrimPktHeader *pkt = NULL;

    /* copy complete packet header to the linear buffer */
    while ((need_read = sizeof(MrimPktHeader) - md->server.rx_pkt_buf->len) > 0) {
        if (!(available = purple_circ_buffer_get_max_read(md->server.rx_buf))) {
            return NULL;
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                MIN(need_read, available) 
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, MIN(need_read, available));
        }
    }
    pkt = (MrimPktHeader*) md->server.rx_pkt_buf->str;

    /* copy whole packet to the linear buffer */
    while ((need_read = PKT_LEN(pkt) - md->server.rx_pkt_buf->len) > 0) {
        if (!(available = purple_circ_buffer_get_max_read(md->server.rx_buf))) {
            return NULL;
        }
        else {
            md->server.rx_pkt_buf = g_string_append_len(
                md->server.rx_pkt_buf,
                md->server.rx_buf->outptr,
                MIN(need_read, available)
            );
            purple_circ_buffer_mark_read(md->server.rx_buf, MIN(need_read, available));
        }
    }

    /* ok, now we have complete packet. copy it and empty buffer */
    pkt = g_memdup(md->server.rx_pkt_buf->str, md->server.rx_pkt_buf->len);
    g_string_truncate(md->server.rx_pkt_buf, 0);

    return pkt;
}

static void
_read_header(MrimPktHeader *pkt, MrimPktHeader *loc, guint32 *pos)
{
    loc->magic = GUINT32_FROM_LE(pkt->magic);
    loc->proto = GUINT32_FROM_LE(pkt->proto);
    loc->seq = GUINT32_FROM_LE(pkt->seq);
    loc->msg = GUINT32_FROM_LE(pkt->msg);
    loc->dlen = GUINT32_FROM_LE(pkt->dlen);
    memcpy(loc->reserved, pkt->reserved, 16);
    *pos += sizeof(MrimPktHeader);
}

static guint32
_read_ul(MrimPktHeader *pkt, guint32 *pos)
{
    guint32 val = *( (guint32*) (((gchar*)pkt) + *pos) );
    *pos += sizeof(guint32);
    return val;
}

static void
_skip_ul(MrimPktHeader *pkt, guint32 *pos)
{
    *pos += sizeof(guint32);
}

static gchar*
_read_lps(MrimPktHeader *pkt, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (((gchar*)pkt) + *pos);
    *pos += LPS_LEN(lps);
    return _lps2str(lps);
}

static void
_skip_lps(MrimPktHeader *pkt, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (((gchar*)pkt) + *pos);
    *pos += LPS_LEN(lps);
}

static gchar*
_read_str(MrimPktHeader *pkt, guint32 *pos)
{
    gchar *str = g_strdup(((gchar*)pkt) + *pos);
    *pos += strlen(str);
    return str;
}

static void
_skip_str(MrimPktHeader *pkt, guint32 *pos)
{
    gchar *str = g_strdup(((gchar*)pkt) + *pos);
    *pos += strlen(str);
}

static gboolean
_skip_by_mask(MrimPktHeader *pkt, guint32 *pos, gchar *mask)
{
    guint32 i = 0;
    for (i = 0; i < strlen(mask); i++) {
        switch (mask[i]) {
            case 'u':
                _skip_ul(pkt, pos);
                break;
            case 's':
                _skip_lps(pkt, pos);
                break;
            case 'z':
                _skip_str(pkt, pos);
                break;
            default:
                return FALSE;
                break;
        }
    }
    return TRUE;
}

/* particular packets */

static MrimPktHelloAck*
_parse_hello_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktHelloAck *loc = g_new0(MrimPktHelloAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->timeout = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_hello_ack(MrimPktHelloAck *loc)
{
    g_free(loc);
}

static MrimPktLoginAck*
_parse_login_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktLoginAck *loc = g_new0(MrimPktLoginAck, 1);
    _read_header(pkt, &loc->header, &pos);
    return loc;
}

static void
_free_login_ack(MrimPktLoginAck *loc)
{
    g_free(loc);
}

static MrimPktLoginRej*
_parse_login_rej(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktLoginRej *loc = g_new0(MrimPktLoginRej, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->reason = _read_lps(pkt, &pos);
    return loc;
}

static MrimPktMessageAck*
_parse_message_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktMessageAck *loc = g_new0(MrimPktMessageAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->msg_id = _read_ul(pkt, &pos);
    loc->flags = _read_ul(pkt, &pos);
    loc->from = _read_lps(pkt, &pos);
    loc->message = _read_lps(pkt, &pos);
    loc->rtf_message = _read_lps(pkt, &pos);
    return loc;
}

static void
_free_login_rej(MrimPktLoginRej *loc)
{
    g_free(loc->reason);
    g_free(loc);
}

static void
_free_message_ack(MrimPktMessageAck *loc)
{
    g_free(loc->from);
    g_free(loc->message);
    g_free(loc->rtf_message);
    g_free(loc);
}

static MrimPktUserStatus*
_parse_user_status(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktUserStatus *loc = g_new0(MrimPktUserStatus, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    loc->email = _read_lps(pkt, &pos);
    return loc;
}

static MrimPktLogout*
_parse_logout(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktLogout *loc = g_new0(MrimPktLogout, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->reason = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_user_status(MrimPktUserStatus *loc)
{
    g_free(loc->email);
    g_free(loc);
}

static void
_free_logout(MrimPktLogout *loc)
{
    g_free(loc);
}

static MrimPktConnectionParams*
_parse_connection_params(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktConnectionParams *loc = g_new0(MrimPktConnectionParams, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->timeout = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_connection_params(MrimPktConnectionParams *loc)
{
    g_free(loc);
}

static MrimPktUserInfo*
_parse_user_info(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    gchar *key = NULL, *val = NULL;
    MrimPktUserInfo *loc = g_new0(MrimPktUserInfo, 1);
    loc->info = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    _read_header(pkt, &loc->header, &pos);
    while (pos < loc->header.dlen) {
        key = _read_lps(pkt, &pos);
        val = _read_lps(pkt, &pos);
        g_hash_table_insert(((MrimPktUserInfo *)loc)->info, key, val);
    }
    return loc;
}

static void
_free_user_info(MrimPktUserInfo *loc)
{
    g_hash_table_destroy(loc->info);
    g_free(loc);
}

static MrimPktContactList*
_parse_contact_list(MrimData *md, MrimPktHeader *pkt)
{
    MrimPktContactList *loc = NULL;
    guint32 pos = 0, groups_count = 0, i = 0, j = 0;
    gchar *group_mask = NULL, *contact_mask = NULL;
    MrimGroup *group = NULL;
    MrimContact *contact = NULL;
    
    loc = g_new0(MrimPktContactList, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    groups_count = _read_ul(pkt, &pos);
    group_mask = _read_lps(pkt, &pos);
    contact_mask = _read_lps(pkt, &pos);

    for (i = 0; i < groups_count; i++) {
         group = g_new0(MrimGroup, 1);
         group->flags = _read_ul(pkt, &pos);
         group->name = _read_lps(pkt, &pos);
         loc->groups = g_list_append(loc->groups, group);
         if (!_skip_by_mask(pkt, &pos, group_mask + 2)) {
            fprintf(stderr, "WARN: wrong pkt content\n");
         }
    }
    loc->groups = g_list_first(loc->groups);

    while (pos < loc->header.dlen) {
        contact = g_new0(MrimContact, 1);
        contact->flags = _read_ul(pkt, &pos);
        contact->group_id = _read_ul(pkt, &pos);
        contact->email = _read_lps(pkt, &pos);
        contact->nick = _read_lps(pkt, &pos);
        contact->server_flags = _read_ul(pkt, &pos);
        contact->status = _read_ul(pkt, &pos);
        loc->contacts = g_list_append(loc->contacts, contact);
        if (!_skip_by_mask(pkt, &pos, contact_mask + 6)) {
            fprintf(stderr, "WARN: wrong pkt content\n");
        }
    }
    loc->contacts = g_list_first(loc->contacts);

    g_free(group_mask);
    g_free(contact_mask);
    return loc;
}

static void
_free_contact_list(MrimPktContactList *loc)
{
    MrimGroup *group = NULL;
    MrimContact *contact = NULL;
    GList *node = NULL;

    node = g_list_first(loc->groups);
    while (node) {
        group = (MrimGroup *) node->data;
        g_free(group->name);
        g_free(group);
        node = g_list_next(node);
    }
    g_list_free(loc->groups);

    node = g_list_first(loc->contacts);
    while (node) {
        contact = (MrimContact *) node->data;
        g_free(contact->email);
        g_free(contact->nick);
        g_free(contact);
        node = g_list_next(node);
    }
    g_list_free(loc->contacts);
    g_free(loc);
}

static MrimPktAddContactAck*
_parse_add_contact_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktAddContactAck *loc = g_new0(MrimPktAddContactAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    loc->contact_id = _read_ul(pkt, &pos);
    return loc;
}

static MrimPktModifyContactAck*
_parse_modify_contact_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktModifyContactAck *loc = g_new0(MrimPktModifyContactAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    return loc;
}

static MrimPktAuthorizeAck*
_parse_authorize_ack(MrimData *md, MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktAuthorizeAck *loc = g_new0(MrimPktAuthorizeAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->email = _read_lps(pkt, &pos);
    return loc;
}

static void
_free_add_contact_ack(MrimPktAddContactAck *loc)
{
    g_free(loc);
}

static void
_free_modify_contact_ack(MrimPktModifyContactAck *loc)
{
    g_free(loc);
}

static void
_free_authorize_ack(MrimPktAuthorizeAck *loc)
{
    g_free(loc->email);
    g_free(loc);
}

MrimPktHeader*
mrim_pkt_parse(MrimData *md)
{
    MrimPktHeader *pkt = NULL;
    MrimPktHeader *loc = NULL;

    if (!(pkt = _collect(md))) {
        return NULL;
    }

fprintf(stderr, "parsing 0x%08x\n", GUINT32_FROM_LE(pkt->msg));

    switch (GUINT32_FROM_LE(pkt->msg)) {
        case MRIM_CS_HELLO_ACK:
            loc = (MrimPktHeader*) _parse_hello_ack(md, pkt);
            break;
        case MRIM_CS_LOGIN_ACK:
            loc = (MrimPktHeader*) _parse_login_ack(md, pkt);
            break;
        case MRIM_CS_LOGIN_REJ:
            loc = (MrimPktHeader*) _parse_login_rej(md, pkt);
            break;
        case MRIM_CS_MESSAGE_ACK:
            loc = (MrimPktHeader*) _parse_message_ack(md, pkt);
            break;
        case MRIM_CS_MESSAGE_STATUS:
            break;
        case MRIM_CS_USER_STATUS:
            loc = (MrimPktHeader*) _parse_user_status(md, pkt);
            break;
        case MRIM_CS_LOGOUT:
            loc = (MrimPktHeader*) _parse_logout(md, pkt);
            break;
        case MRIM_CS_CONNECTION_PARAMS:
            loc = (MrimPktHeader*) _parse_connection_params(md, pkt);
            break;
        case MRIM_CS_USER_INFO:
            loc = (MrimPktHeader*) _parse_user_info(md, pkt);
            break;
        case MRIM_CS_ADD_CONTACT_ACK:
            loc = (MrimPktHeader*) _parse_add_contact_ack(md, pkt);
            break;
        case MRIM_CS_MODIFY_CONTACT_ACK:
            loc = (MrimPktHeader*) _parse_modify_contact_ack(md, pkt);
            break;
        case MRIM_CS_OFFLINE_MESSAGE_ACK:
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            loc = (MrimPktHeader*) _parse_authorize_ack(md, pkt);
            break;
        case MRIM_CS_MPOP_SESSION:
            break;
        case MRIM_CS_ANKETA_INFO:
            break;
        case MRIM_CS_CONTACT_LIST2:
            loc = (MrimPktHeader*) _parse_contact_list(md, pkt);
            break;
        default:
            #ifdef ENABLE_MRIM_DEBUG
            purple_debug_info("mrim", "parsing unsupported type of packet %x\n", 
                (guint) GUINT32_FROM_LE(pkt->msg));
            #endif
            break;
            
    }
    
    g_free(pkt);
    return loc;
}

void
mrim_pkt_free(MrimPktHeader *loc) 
{
    if (loc) {
        switch (loc->msg) {
            case MRIM_CS_HELLO_ACK:
                _free_hello_ack((MrimPktHelloAck*) loc);
                break;
            case MRIM_CS_LOGIN_ACK:
                _free_login_ack((MrimPktLoginAck*) loc);
                break;
            case MRIM_CS_LOGIN_REJ:
                _free_login_rej((MrimPktLoginRej*) loc);
                break;
            case MRIM_CS_MESSAGE_ACK:
                _free_message_ack((MrimPktMessageAck*) loc);
                break;
            case MRIM_CS_MESSAGE_STATUS:
                break;
            case MRIM_CS_USER_STATUS:
                _free_user_status((MrimPktUserStatus*) loc);
                break;
            case MRIM_CS_LOGOUT:
                _free_logout((MrimPktLogout*) loc);
                break;
            case MRIM_CS_CONNECTION_PARAMS:
                _free_connection_params((MrimPktConnectionParams*) loc);
                break;
            case MRIM_CS_USER_INFO:
                _free_user_info((MrimPktUserInfo*) loc);
                break;
            case MRIM_CS_ADD_CONTACT_ACK:
                _free_add_contact_ack((MrimPktAddContactAck*) loc);
                break;
            case MRIM_CS_MODIFY_CONTACT_ACK:
                _free_modify_contact_ack((MrimPktModifyContactAck*) loc);
                break;
            case MRIM_CS_OFFLINE_MESSAGE_ACK:
                break;
            case MRIM_CS_AUTHORIZE_ACK:
                _free_authorize_ack((MrimPktAuthorizeAck*) loc);
                break;
            case MRIM_CS_MPOP_SESSION:
                break;
            case MRIM_CS_ANKETA_INFO:
                break;
            case MRIM_CS_CONTACT_LIST2:
                _free_contact_list((MrimPktContactList*) loc);
                break;
            default:
                #ifdef ENABLE_MRIM_DEBUG
                purple_debug_info("mrim", "freeing unsupported type of packet %u\n", 
                    (guint) loc->msg);
                #endif
                break;
        }
    }
}
