#include <glib.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>
#include "pkt.h"

/* Common utils */

#define MAX_GROUP 20
#define UIDL_LEN 8
#define PKT_LEN(pkt) (GUINT32_FROM_LE(pkt->dlen) + sizeof(MrimPktHeader))
#define LPS_LEN(lps) (GUINT32_FROM_LE((lps)->length) + sizeof((lps)->length))

typedef struct {
    guint32 length;
    gchar data[];
} MrimPktLps;

static MrimPktLps*
_str2lps(const gchar *str, const gchar *charset)
{
    gchar *data = NULL;
    guint32 data_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    MrimPktLps *lps = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);
    data = g_convert_with_fallback(str, strlen(str), charset, local_charset, "?", 
                            NULL, &data_len, &err);
    if (!data) {
        purple_debug_error("mrim", "_str2lps: bad encoding %s\n", err->message);
        return NULL;
    }

    lps = (MrimPktLps*) g_malloc0(sizeof(guint32) + data_len);
    lps->length = GUINT32_TO_LE(data_len);
    memcpy(lps->data, data, data_len);
    g_free(data);
    return lps;
}

static MrimPktLps*
_str2lps_cp1251(const gchar *str)
{
    return _str2lps(str, "WINDOWS-1251");
}

static MrimPktLps*
_str2lps_utf16(const gchar *str)
{
    return _str2lps(str, "UTF-16LE");
}

static MrimPktLps*
_vmem2lps(const guint chunks, ...)
{
    guint32 total = 0, i = 0, data_len = 0;
    gpointer data = NULL;
    MrimPktLps *lps = NULL;
    va_list ap;

    va_start(ap, chunks);
    for (i = 0; i < chunks; i++) {
        va_arg(ap, gpointer); //skip pointer
        total += va_arg(ap, guint32);
    }
    va_end(ap);

    lps  = (MrimPktLps*) g_malloc0(sizeof(guint32) + total);
    lps->length = GUINT32_TO_LE(total);
    total = 0;

    va_start(ap, chunks);
    for (i = 0; i < chunks; i++) {
        data = va_arg(ap, gpointer);
        data_len = va_arg(ap, guint32);
        memcpy(lps->data + total, data, data_len);
        total += data_len;
    }
    va_end(ap);

    return lps;
}

static gchar*
_lps2str(MrimPktLps *lps, const gchar* charset)
{
    gchar *str = NULL;
    guint32 str_len = 0;
    G_CONST_RETURN char *local_charset = NULL;
    GError *err = NULL;

    g_get_charset(&local_charset);

    str = g_convert_with_fallback(lps->data, GUINT32_FROM_LE(lps->length), 
            local_charset, charset, "?", NULL, &str_len, &err);

    if (!str) {
        purple_debug_error("mrim", "_lps2str: bad encoding %s\n", err->message);
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

    if (!(lps_login = _str2lps_cp1251(login))) {
        return;
    }
    if (!(lps_pass = _str2lps_cp1251(pass))) {
        g_free(lps_login);
        return;
    }
    status = GUINT32_TO_LE(status);
    if (!(lps_agent = _str2lps_cp1251(agent))) {
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
                    const gchar *email, const gchar *nick)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL, *lps_nick = NULL, *lps_unused = NULL;

    flags = GUINT32_TO_LE(flags);
    group_id = GUINT32_TO_LE(group_id);
    if (!(lps_email = _str2lps_cp1251(email))) {
        return;
    }
    if (!(lps_nick = _str2lps_cp1251(nick))) {
        g_free(lps_email);
        return;
    }
    if (!(lps_unused = _str2lps_cp1251(""))) {
        g_free(lps_nick);
        g_free(lps_email);
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_ADD_CONTACT, 
        2 * sizeof(guint32) + LPS_LEN(lps_email) 
        + LPS_LEN(lps_nick) + LPS_LEN(lps_unused));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, &group_id, sizeof(group_id));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));
    purple_circ_buffer_append(md->server.tx_buf, lps_nick, LPS_LEN(lps_nick));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));

    g_free(lps_email);
    g_free(lps_nick);
    g_free(lps_unused);
}

void
mrim_pkt_build_add_chat(MrimData *md, guint32 flags, const gchar *nick,
                    const gboolean private_chat)
{
    MrimPktHeader header;
    MrimPktLps *lps_nick = NULL, *lps_unused = NULL, *lps_self_email = NULL,
                *lps_members_cont = NULL, *lps_chat_cont = NULL;
    guint32 group_id = GUINT32_TO_LE(0);
    guint32 members_count = GUINT32_TO_LE(0);
    flags = GUINT32_TO_LE(flags);


    if (!(lps_unused = _str2lps_cp1251(""))) {
        return;
    }
    if (!(lps_nick = _str2lps_utf16(nick))) {
        g_free(lps_unused);
        return;
    }
    if (!(lps_self_email = _str2lps_cp1251(purple_account_get_username(md->account)))) {
        g_free(lps_unused);
        g_free(lps_nick);
        return;
    }
    if (!(lps_members_cont = _vmem2lps(1, &members_count, sizeof(members_count)))) {
        g_free(lps_unused);
        g_free(lps_nick);
        g_free(lps_self_email);
        return;
    }
    if (private_chat) {
        lps_chat_cont = _vmem2lps(1, lps_members_cont, LPS_LEN(lps_members_cont));
    }
    else {
        lps_chat_cont = _vmem2lps(2, lps_members_cont, LPS_LEN(lps_members_cont),
                                        lps_self_email, LPS_LEN(lps_self_email));
    }
    if (!lps_chat_cont) {
        g_free(lps_unused);
        g_free(lps_nick);
        g_free(lps_self_email);
        g_free(lps_members_cont);
        return;
    }

    _init_header(&header, ++md->tx_seq, MRIM_CS_ADD_CONTACT, 
        2 * sizeof(guint32) + LPS_LEN(lps_unused) 
        + LPS_LEN(lps_nick) + 3 * LPS_LEN(lps_unused) 
        + LPS_LEN(lps_chat_cont));

    // I know this is ugly, but this f**king server doesn't want to create chats
    // It starts chat support from 0x14 minor version
    header.proto = PROTO_MAKE_VERSION(PROTO_VERSION_MAJOR, 0x14);
    
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, &group_id, sizeof(group_id));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));
    purple_circ_buffer_append(md->server.tx_buf, lps_nick, LPS_LEN(lps_nick));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));
    purple_circ_buffer_append(md->server.tx_buf, lps_chat_cont, LPS_LEN(lps_chat_cont));

    g_free(lps_unused);
    g_free(lps_nick);
    g_free(lps_self_email);
    g_free(lps_members_cont);
    g_free(lps_chat_cont);
}

void
mrim_pkt_build_modify_contact(MrimData *md, guint32 id, guint32 flags, guint32 group_id, 
                    const gchar *email, const gchar *nick)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL, *lps_nick = NULL, *lps_unused = NULL;

    id = GUINT32_TO_LE(id);
    flags = GUINT32_TO_LE(flags);
    group_id = GUINT32_TO_LE(group_id);
    if (!(lps_email = _str2lps_cp1251(email))) {
        return;
    }
    if (!(lps_nick = _str2lps_cp1251(nick))) {
        g_free(lps_email);
        return;
    }
    if (!(lps_unused = _str2lps_cp1251(""))) {
        g_free(lps_nick);
        g_free(lps_email);
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_MODIFY_CONTACT, 
        3 * sizeof(guint32) + LPS_LEN(lps_email) 
        + LPS_LEN(lps_nick) + LPS_LEN(lps_unused));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &id, sizeof(id));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, &group_id, sizeof(group_id));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));
    purple_circ_buffer_append(md->server.tx_buf, lps_nick, LPS_LEN(lps_nick));
    purple_circ_buffer_append(md->server.tx_buf, lps_unused, LPS_LEN(lps_unused));

    g_free(lps_email);
    g_free(lps_nick);
    g_free(lps_unused);
}

void
mrim_pkt_build_message(MrimData *md, guint32 flags, const gchar *to, 
                        const gchar *message, const gchar *rtf_message)
{
    MrimPktHeader header;
    MrimPktLps *lps_to = NULL, *lps_message = NULL, *lps_rtf_message = NULL;

    flags = GUINT32_TO_LE(flags);
    if (!(lps_to = _str2lps_cp1251(to))) {
        return;
    }
    if (!(lps_message = _str2lps_cp1251(message))) {
        g_free(lps_to);
        return;
    }
    if (!(lps_rtf_message = _str2lps_cp1251(rtf_message))) {
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
mrim_pkt_build_chat_get_members(MrimData *md, guint32 flags, const gchar* email)
{
    MrimPktHeader header;
    MrimPktLps *lps_to = NULL, *lps_message = NULL, 
               *lps_rtf_message = NULL, *lps_chat = NULL;

    flags = GUINT32_TO_LE(flags);
    if (!(lps_to = _str2lps_cp1251(email))) {
        return;
    }
    
    if (!(lps_message = lps_rtf_message = _str2lps_cp1251(""))) {
        return;
    }

    guint32 subtype = GUINT32_TO_LE(MULTICHAT_GET_MEMBERS);
    if (!(lps_chat = _vmem2lps(1, &subtype, sizeof(subtype)))) {
        return;
    }

    _init_header(&header, ++md->tx_seq, MRIM_CS_MESSAGE, sizeof(flags) + LPS_LEN(lps_to)
        + LPS_LEN(lps_message) + LPS_LEN(lps_rtf_message) + LPS_LEN(lps_chat));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, &flags, sizeof(flags));
    purple_circ_buffer_append(md->server.tx_buf, lps_to, LPS_LEN(lps_to));
    purple_circ_buffer_append(md->server.tx_buf, lps_message, LPS_LEN(lps_message));
    purple_circ_buffer_append(md->server.tx_buf, lps_rtf_message, LPS_LEN(lps_rtf_message));
    purple_circ_buffer_append(md->server.tx_buf, lps_chat, LPS_LEN(lps_chat));

    g_free(lps_to);
    g_free(lps_message);
    g_free(lps_chat);
}

void
mrim_pkt_build_authorize(MrimData *md, const gchar *email)
{
    MrimPktHeader header;
    MrimPktLps *lps_email = NULL;

    if (!(lps_email = _str2lps_cp1251(email))) {
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_AUTHORIZE, LPS_LEN(lps_email));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_email, LPS_LEN(lps_email));

    g_free(lps_email);
}

void
mrim_pkt_build_wp_request(MrimData *md, guint32 count, ...)
{
    MrimPktHeader header;
    va_list rest;
    guint32 i = 0, j = 0, param_len = 0;
    gboolean found = FALSE;
    guint32 key;
    MrimPktLps *val;
    GHashTable *params = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    guint32 order[] = {
        MRIM_CS_WP_REQUEST_PARAM_USER,
        MRIM_CS_WP_REQUEST_PARAM_DOMAIN,
        MRIM_CS_WP_REQUEST_PARAM_NICKNAME,
        MRIM_CS_WP_REQUEST_PARAM_FIRSTNAME,
        MRIM_CS_WP_REQUEST_PARAM_LASTNAME,
        MRIM_CS_WP_REQUEST_PARAM_SEX,
        MRIM_CS_WP_REQUEST_PARAM_DATE1,
        MRIM_CS_WP_REQUEST_PARAM_DATE2,
        MRIM_CS_WP_REQUEST_PARAM_CITY_ID,
        MRIM_CS_WP_REQUEST_PARAM_ZODIAC,
        MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_MONTH,
        MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_DAY,
        MRIM_CS_WP_REQUEST_PARAM_COUNTRY_ID,
        MRIM_CS_WP_REQUEST_PARAM_ONLINE,
    };

    va_start(rest, count);
    for (i = 0; i < count; i++) {
        key = va_arg(rest, guint32);
        val = _str2lps_cp1251(va_arg(rest, gchar*));
        for (found = FALSE, j = 0; j < sizeof(order) / sizeof(guint32); j++) {
            if (order[j] == key) {
                found = TRUE;
            }
        }
        if (found) {
            g_hash_table_replace(params, (gpointer) key, val);
            param_len += sizeof(key) + LPS_LEN(val);
        }
    }
    va_end(rest);
    _init_header(&header, ++md->tx_seq, MRIM_CS_WP_REQUEST, param_len);
    
    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    for (i = 0; i < sizeof(order) / sizeof(guint32); i++) {
        key = order[i];
        if (val = g_hash_table_lookup(params, (gpointer) key)) {
            key = GUINT32_TO_LE(key);
            purple_circ_buffer_append(md->server.tx_buf, &key, sizeof(key));
            purple_circ_buffer_append(md->server.tx_buf, val, LPS_LEN(val));
        }
    }

    g_hash_table_destroy(params);
}

void
mrim_pkt_build_message_recv(MrimData *md, gchar *from, guint32 msg_id)
{
    MrimPktHeader header;
    MrimPktLps *lps_from = NULL;

    msg_id = GUINT32_TO_LE(msg_id);
    if (!(lps_from = _str2lps_cp1251(from))) {
        return;
    }
    _init_header(&header, ++md->tx_seq, MRIM_CS_MESSAGE_RECV, sizeof(msg_id) + LPS_LEN(lps_from));

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, lps_from, LPS_LEN(lps_from));
    purple_circ_buffer_append(md->server.tx_buf, &msg_id, sizeof(msg_id));

    g_free(lps_from);
}

void
mrim_pkt_build_offline_message_del(MrimData *md, Uidl uidl)
{
    MrimPktHeader header;

    _init_header(&header, ++md->tx_seq, MRIM_CS_DELETE_OFFLINE_MESSAGE, UIDL_LEN);

    purple_circ_buffer_append(md->server.tx_buf, &header, sizeof(header));
    purple_circ_buffer_append(md->server.tx_buf, uidl, UIDL_LEN);
}

/* Server to Client messages */

/* Collect bytes in rx_pkt_buf for just one packet 
   Returns NULL if there are not sufficient bytes in circle buffer
*/

static MrimPktHeader*
_collect(MrimData *md)
{
    guint32 available = 0;
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

static void
_read_chat_header(MrimPktChatHeader *pkt, MrimPktChatHeader *loc, guint32 *pos)
{
    loc->dlen = GUINT32_FROM_LE(pkt->dlen);
    loc->type = GUINT32_FROM_LE(pkt->type);
    *pos += sizeof(pkt->dlen) + sizeof(pkt->type);
}

static guint32
_read_ul(gpointer ptr, guint32 *pos)
{
    guint32 val = *( (guint32*) (ptr + *pos) );
    *pos += sizeof(guint32);
    return val;
}

static void
_skip_ul(gpointer ptr, guint32 *pos)
{
    *pos += sizeof(guint32);
}

static gchar*
_read_lps_cp1251(gpointer ptr, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (ptr + *pos);
    *pos += LPS_LEN(lps);
    return _lps2str(lps, "WINDOWS-1251");
}

static gchar*
_read_lps_utf16(gpointer ptr, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (ptr + *pos);
    *pos += LPS_LEN(lps);
    return _lps2str(lps, "UTF-16LE");
}

static void
_skip_lps(gpointer ptr, guint32 *pos)
{
    MrimPktLps *lps = (MrimPktLps*) (ptr + *pos);
    *pos += LPS_LEN(lps);
}

static gchar*
_read_str(gpointer ptr, guint32 *pos)
{
    gchar *str = g_strdup(ptr + *pos);
    *pos += strlen(str);
    return str;
}

static void
_skip_str(gpointer ptr, guint32 *pos)
{
    *pos += strlen(ptr + *pos + 1);
}

static gboolean
_skip_by_mask(gpointer ptr, guint32 *pos, gchar *mask)
{
    guint32 i = 0;
    for (i = 0; i < strlen(mask); i++) {
        switch (mask[i]) {
            case 'u':
                _skip_ul(ptr, pos);
                break;
            case 's':
                _skip_lps(ptr, pos);
                break;
            case 'z':
                _skip_str(ptr, pos);
                break;
            default:
                return FALSE;
                break;
        }
    }
    return TRUE;
}

static Uidl
_read_uidl(gpointer ptr, guint32 *pos)
{
    Uidl uidl = g_malloc0(UIDL_LEN);
    memcpy(uidl, ptr + *pos, UIDL_LEN);
    *pos += UIDL_LEN;
    return uidl;
}
    
/* chat subpackets */

static MrimPktChatMessage*
_chat_parse_message(MrimPktChatHeader *pkt)
{
    guint32 pos = 0;
    MrimPktChatMessage *loc = g_new0(MrimPktChatMessage, 1);
    _read_chat_header(pkt, &loc->header, &pos);
    loc->sender = _read_lps_cp1251(pkt, &pos); 
    return loc;
}

static void
_chat_free_message(MrimPktChatMessage *loc)
{
    g_free(loc->sender);
    g_free(loc);
    return;
}

static MrimPktChatMembers*
_chat_parse_members(MrimPktChatHeader *pkt)
{
    guint32 pos = 0;
    MrimPktChatMembers *loc = g_new0(MrimPktChatMembers, 1);
    _read_chat_header(pkt, &loc->header, &pos);
    loc->nick = _read_lps_utf16(pkt, &pos); 
    _skip_ul(pkt, &pos); // unknown number
    _skip_ul(pkt, &pos); // seems to be a number of users
    while (pos < loc->header.dlen) {
        gchar *member = _read_lps_cp1251(pkt, &pos);
        loc->members = g_list_append(loc->members, member);
    }
    loc->members = g_list_first(loc->members);
    return loc;
}

static void
_chat_free_members(MrimPktChatMembers *loc)
{
    g_free(loc->nick);
    GList *item = NULL;
    for (item = g_list_first(loc->members); item; item = g_list_next(item)) {
        g_free(item->data);
    }
    g_list_free(loc->members);
    g_free(loc);
    return;
}

static MrimPktChatAddMembers*
_chat_parse_add_members(MrimPktChatHeader* pkt)
{
    guint32 pos = 0;
    MrimPktChatAddMembers *loc = g_new0(MrimPktChatAddMembers, 1);
    _read_chat_header(pkt, &loc->header, &pos);
    loc->sender = _read_lps_cp1251(pkt, &pos); 
    while (pos < loc->header.dlen) {
        gchar *member = _read_lps_cp1251(pkt, &pos);
        loc->members = g_list_append(loc->members, member);
    }
    loc->members = g_list_first(loc->members);
    return loc;
}

static void
_chat_free_add_members(MrimPktChatAddMembers *loc)
{
    GList *item = NULL;
    for (item = g_list_first(loc->members); item; item = g_list_next(item)) {
        g_free(item->data);
    }
    g_list_free(loc->members);
    g_free(loc->sender);
    g_free(loc);
    return;
}

static MrimPktChatAttached*
_chat_parse_attached(MrimPktChatHeader *pkt)
{
    guint32 pos = 0;
    MrimPktChatAttached *loc = g_new0(MrimPktChatAttached, 1);
    _read_chat_header(pkt, &loc->header, &pos);
    loc->member = _read_lps_cp1251(pkt, &pos); 
    return loc;
}

static void
_chat_free_attached(MrimPktChatAttached *loc)
{
    g_free(loc->member);
    g_free(loc);
    return;
}

static MrimPktChatDetached*
_chat_parse_detached(MrimPktChatHeader *pkt)
{
    guint32 pos = 0;
    MrimPktChatDetached *loc = g_new0(MrimPktChatDetached, 1);
    _read_chat_header(pkt, &loc->header, &pos);
    loc->member = _read_lps_cp1251(pkt, &pos); 
    return loc;
}

static void
_chat_free_detached(MrimPktChatDetached *loc)
{
    g_free(loc->member);
    g_free(loc);
    return;
}

static MrimPktChatHeader*
_chat_subpkt_parse(MrimPktChatHeader *pkt)
{
    switch (GUINT32_FROM_LE(pkt->type)) {
        case MULTICHAT_MESSAGE:
            return (MrimPktChatHeader*) _chat_parse_message(pkt);
            break;
        case MULTICHAT_MEMBERS:
            return (MrimPktChatHeader*) _chat_parse_members(pkt);
            break;
        case MULTICHAT_ADD_MEMBERS:
            return (MrimPktChatHeader*) _chat_parse_add_members(pkt);
            break;
        case MULTICHAT_ATTACHED:
            return (MrimPktChatHeader*) _chat_parse_attached(pkt);
            break;
        case MULTICHAT_DETACHED:
            return (MrimPktChatHeader*) _chat_parse_detached(pkt);
            break;
        default:
            #ifdef ENABLE_MRIM_DEBUG
            purple_debug_info("mrim", "parsing unsupported type of chat packet %x\n", type);
            #endif
            return NULL;
            break;
    }
}

void
_chat_subpkt_free(MrimPktChatHeader *loc)
{
    switch (loc->type) {
        case MULTICHAT_MESSAGE:
            return _chat_free_message((MrimPktChatMessage*) loc);
            break;
        case MULTICHAT_MEMBERS:
            return _chat_free_members((MrimPktChatMembers*) loc);
            break;
        case MULTICHAT_ADD_MEMBERS:
            return _chat_free_add_members((MrimPktChatAddMembers*) loc);
            break;
        case MULTICHAT_ATTACHED:
            return _chat_free_attached((MrimPktChatAttached*) loc);
            break;
        case MULTICHAT_DETACHED:
            return _chat_free_detached((MrimPktChatDetached*) loc);
            break;
        default:
            break;
    }
}

/* particular packets */

static MrimPktHelloAck*
_parse_hello_ack(MrimPktHeader *pkt)
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
_parse_login_ack(MrimPktHeader *pkt)
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
_parse_login_rej(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktLoginRej *loc = g_new0(MrimPktLoginRej, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->reason = _read_lps_cp1251(pkt, &pos);
    return loc;
}

static void
_free_login_rej(MrimPktLoginRej *loc)
{
    g_free(loc->reason);
    g_free(loc);
}

static MrimPktMessageAck*
_parse_message_ack(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktMessageAck *loc = g_new0(MrimPktMessageAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->msg_id = _read_ul(pkt, &pos);
    loc->flags = _read_ul(pkt, &pos);
    loc->from = _read_lps_cp1251(pkt, &pos);
    loc->message = _read_lps_cp1251(pkt, &pos);
    if (pos < loc->header.dlen + sizeof(loc->header)) {
        // bug with chat messages: no rtf lps
        loc->rtf_message = _read_lps_cp1251(pkt, &pos);
    }
    if ((pos < loc->header.dlen + sizeof(loc->header)) 
        && loc->flags & MESSAGE_FLAG_MULTICHAT) 
    {
        // it's a multichat message actually
        loc->multichat = _chat_subpkt_parse((MrimPktChatHeader*)(((gchar*) pkt) + pos));
    }
    return loc;
}

static void
_free_message_ack(MrimPktMessageAck *loc)
{
    g_free(loc->from);
    g_free(loc->message);
    if (loc->rtf_message) {
        g_free(loc->rtf_message);
    }
    if (loc->multichat) {
        _chat_subpkt_free(loc->multichat);
    }
    g_free(loc);
}

static MrimPktOfflineMessageAck*
_parse_offline_message_ack(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    gchar *mail = NULL, *p = NULL, *k = NULL, *v = NULL, *ks = NULL, *boundary = NULL;
    enum {KEY_SKAN, WHITE_SKIP, VAL_SKAN, BODY, STOP} state;

    MrimPktOfflineMessageAck *loc = g_new0(MrimPktOfflineMessageAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->uidl = _read_uidl(pkt, &pos);
    mail = _read_lps_cp1251(pkt, &pos);

    /* parse offline message content */
    for (p = k = mail, state = KEY_SKAN; *p && state != STOP; p++) {
        /* DEBUG
        fprintf(stderr, "state %s char '%c'\n", state == KEY_SKAN ? "KEY_SKAN" : 
                                                state == WHITE_SKIP ? "WHITE_SKIP" : 
                                                state == VAL_SKAN ? "VAL_SKAN" : 
                                                state == BODY ? "BODY" : "STOP", 
                                                *p);
        fprintf(stderr, "\tp=%p\tk=%p\tks=%p\tv=%p\n", p, k, ks, v);
        */
        switch (state) {
            case KEY_SKAN:
                /* reading header key */
                if (*p == ':') {
                    ks = p;
                    state = WHITE_SKIP;
                }
                else if (*p == '\n') {
                    state = BODY;
                }
                break;
            case WHITE_SKIP:
                /* skipping white spaces before value */
                if (*p != ' ' && *p != '\t') {
                    v = p;
                    state = VAL_SKAN;
                }
                break;
            case VAL_SKAN:
                /* reading header value */
                if (*p == '\n') {
                    if (0 == g_ascii_strncasecmp(k, "From", ks - k)) {
                        loc->from = g_strndup(v, p - v);
                    }
                    else if (0 == g_ascii_strncasecmp(k, "Boundary", ks - k)) {
                        gchar *boundary_tmp = g_strndup(v, p - v);
                        boundary = g_strdup_printf("--%s--", boundary_tmp);
                        g_free(boundary_tmp);
                    }
                    else if (0 == g_ascii_strncasecmp(k, "X-MRIM-Flags", ks - k)) {
                        loc->flags = (guint32) atol(v);
                    }
                    else if (0 == g_ascii_strncasecmp(k, "Date", ks - k)) {
                        gchar *date = strndup(v, p - v);
                        gchar *oldlocale = setlocale(LC_TIME, NULL);
                        struct tm tm;
                        setlocale(LC_TIME, "C");
                        strptime(date, "%a, %d %b %Y %H:%M:%S", &tm);
                        setlocale(LC_TIME, oldlocale);
                        loc->time = mktime(&tm);
                        g_free(date);
                    }
                    state = KEY_SKAN;
                    k = p + 1;
                }
                break;
            case BODY:
                if (boundary) {
                    if (v = g_strstr_len(p, -1, boundary)) {
                        loc->message = g_strndup(p, v - p);
                        p = v + strlen(boundary);
                        if (v = g_strstr_len(p, -1, boundary)) {
                            loc->rtf_message = g_strndup(p, v - p);
                        }
                        else {
                            loc->rtf_message = g_strdup(p);
                        }
                    }
                    else {
                        loc->message = g_strdup(p);
                    }
                }
                state = STOP;
                break;
            case STOP:
                break;
        }
    }
    g_free(boundary);
    g_free(mail);
    return loc;
}

static void
_free_offline_message_ack(MrimPktOfflineMessageAck* loc)
{
    g_free(loc->from);
    g_free(loc->message);
    if (loc->rtf_message) {
        g_free(loc->rtf_message);
    }
    g_free(loc);
}

static MrimPktMessageStatus*
_parse_message_status(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktMessageStatus *loc = g_new0(MrimPktMessageStatus, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_message_status(MrimPktMessageStatus *loc)
{
    g_free(loc);
}

static MrimPktUserStatus*
_parse_user_status(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktUserStatus *loc = g_new0(MrimPktUserStatus, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    loc->email = _read_lps_cp1251(pkt, &pos);
    return loc;
}

static void
_free_user_status(MrimPktUserStatus *loc)
{
    g_free(loc->email);
    g_free(loc);
}

static MrimPktLogout*
_parse_logout(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktLogout *loc = g_new0(MrimPktLogout, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->reason = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_logout(MrimPktLogout *loc)
{
    g_free(loc);
}

static MrimPktConnectionParams*
_parse_connection_params(MrimPktHeader *pkt)
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
_parse_user_info(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    gchar *key = NULL, *val = NULL;
    MrimPktUserInfo *loc = g_new0(MrimPktUserInfo, 1);
    loc->info = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    _read_header(pkt, &loc->header, &pos);
    while (pos < loc->header.dlen + sizeof(loc->header)) {
        key = _read_lps_cp1251(pkt, &pos);
        val = _read_lps_cp1251(pkt, &pos);
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

static MrimPktAnketaInfo*
_parse_anketa_info(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    int i = 0;
    GHashTable *user = NULL;
    gchar *val = NULL;
    MrimPktAnketaInfo *loc = g_new0(MrimPktAnketaInfo, 1);

    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    loc->field_num = _read_ul(pkt, &pos);
    loc->max_rows = _read_ul(pkt, &pos);
    loc->server_time = (time_t) _read_ul(pkt, &pos);

    for (i = 0; i < loc->field_num; i++) {
        loc->keys = g_list_append(loc->keys, _read_lps_cp1251(pkt, &pos));
    }
    loc->keys = g_list_first(loc->keys);

    while (pos < loc->header.dlen + sizeof(loc->header)) {
        user = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
        for (i = 0; i < loc->field_num; i++) {
            g_hash_table_insert(user, g_list_nth_data(loc->keys, i), _read_lps_cp1251(pkt, &pos));
        }
        loc->users = g_list_append(loc->users, user);
    }
    loc->users = g_list_first(loc->users);

    return loc;
}

static void
_free_anketa_info(MrimPktAnketaInfo *loc)
{
    GList *item = NULL;
    for (item = g_list_first(loc->keys); item; item = g_list_next(item)) {
        g_free(item->data);
    }
    g_list_free(loc->keys);
    for (item = g_list_first(loc->users); item; item = g_list_next(item)) {
        g_hash_table_destroy((GHashTable*) item->data);
    }
    g_list_free(loc->users);
    g_free(loc);
}


static MrimPktContactList*
_parse_contact_list(MrimPktHeader *pkt)
{
    MrimPktContactList *loc = NULL;
    guint32 pos = 0, groups_count = 0, id = 0;
    gchar *group_mask = NULL, *contact_mask = NULL;

    guint32 group_id = 0, flags = 0, server_flags = 0, status = 0;
    gchar *nick = NULL, *email = NULL;
    MrimGroup *group = NULL;
    MrimContact *contact = NULL;
    
    loc = g_new0(MrimPktContactList, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    groups_count = _read_ul(pkt, &pos);
    group_mask = _read_lps_cp1251(pkt, &pos);
    contact_mask = _read_lps_cp1251(pkt, &pos);

    for (id = 0; id < groups_count; id++) {
         flags = _read_ul(pkt, &pos);
         nick = _read_lps_cp1251(pkt, &pos);
         MrimGroup *group = mrim_group_new(id, flags, nick);
         g_free(nick);
         loc->groups = g_list_append(loc->groups, group);
         if (!_skip_by_mask(pkt, &pos, group_mask + 2)) {
            purple_debug_error("mrim", "parse_contact_list: wrong pkt content\n");
         }
    }
    loc->groups = g_list_first(loc->groups);

    for (id = 0; pos < loc->header.dlen + sizeof(loc->header); id++) {
        flags = _read_ul(pkt, &pos);
        group_id = _read_ul(pkt, &pos);
        email = _read_lps_cp1251(pkt, &pos);
        nick = _read_lps_cp1251(pkt, &pos);
        server_flags = _read_ul(pkt, &pos);
        status = _read_ul(pkt, &pos);
        contact = mrim_contact_new(MAX_GROUP + id, flags, server_flags, status,
                                    group_id, email, nick);
        g_free(email);
        g_free(nick);
        loc->contacts = g_list_append(loc->contacts, contact);
        if (!_skip_by_mask(pkt, &pos, contact_mask + 6)) {
            purple_debug_error("mrim", "parse_contact_list: wrong pkt content\n");
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
    /* groups and contacts should be freed in main code */
    g_list_free(loc->groups);
    g_list_free(loc->contacts);
    g_free(loc);
}

static MrimPktAddContactAck*
_parse_add_contact_ack(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktAddContactAck *loc = g_new0(MrimPktAddContactAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    loc->contact_id = _read_ul(pkt, &pos);
    if (pos < loc->header.dlen + sizeof(loc->header)) {
        loc->contact_email = _read_lps_cp1251(pkt, &pos);
    }
    return loc;
}

static void
_free_add_contact_ack(MrimPktAddContactAck *loc)
{
    if (loc->contact_email) {
        g_free(loc->contact_email);
    }
    g_free(loc);
}

static MrimPktModifyContactAck*
_parse_modify_contact_ack(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktModifyContactAck *loc = g_new0(MrimPktModifyContactAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->status = _read_ul(pkt, &pos);
    return loc;
}

static void
_free_modify_contact_ack(MrimPktModifyContactAck *loc)
{
    g_free(loc);
}

static MrimPktAuthorizeAck*
_parse_authorize_ack(MrimPktHeader *pkt)
{
    guint32 pos = 0;
    MrimPktAuthorizeAck *loc = g_new0(MrimPktAuthorizeAck, 1);
    _read_header(pkt, &loc->header, &pos);
    loc->email = _read_lps_cp1251(pkt, &pos);
    return loc;
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
    
    purple_debug_misc("mrim", "mrim_pkt_parse: packet received 0x%08x\n", 
                    GUINT32_FROM_LE(pkt->msg));

    switch (GUINT32_FROM_LE(pkt->msg)) {
        case MRIM_CS_HELLO_ACK:
            loc = (MrimPktHeader*) _parse_hello_ack(pkt);
            break;
        case MRIM_CS_LOGIN_ACK:
            loc = (MrimPktHeader*) _parse_login_ack(pkt);
            break;
        case MRIM_CS_LOGIN_REJ:
            loc = (MrimPktHeader*) _parse_login_rej(pkt);
            break;
        case MRIM_CS_MESSAGE_ACK:
            loc = (MrimPktHeader*) _parse_message_ack(pkt);
            break;
        case MRIM_CS_MESSAGE_STATUS:
            loc = (MrimPktHeader*) _parse_message_status(pkt);
            break;
        case MRIM_CS_USER_STATUS:
            loc = (MrimPktHeader*) _parse_user_status(pkt);
            break;
        case MRIM_CS_LOGOUT:
            loc = (MrimPktHeader*) _parse_logout(pkt);
            break;
        case MRIM_CS_CONNECTION_PARAMS:
            loc = (MrimPktHeader*) _parse_connection_params(pkt);
            break;
        case MRIM_CS_USER_INFO:
            loc = (MrimPktHeader*) _parse_user_info(pkt);
            break;
        case MRIM_CS_ADD_CONTACT_ACK:
            loc = (MrimPktHeader*) _parse_add_contact_ack(pkt);
            break;
        case MRIM_CS_MODIFY_CONTACT_ACK:
            loc = (MrimPktHeader*) _parse_modify_contact_ack(pkt);
            break;
        case MRIM_CS_OFFLINE_MESSAGE_ACK:
            loc = (MrimPktHeader*) _parse_offline_message_ack(pkt);
            break;
        case MRIM_CS_AUTHORIZE_ACK:
            loc = (MrimPktHeader*) _parse_authorize_ack(pkt);
            break;
        case MRIM_CS_MPOP_SESSION:
            break;
        case MRIM_CS_ANKETA_INFO:
            loc = (MrimPktHeader*) _parse_anketa_info(pkt);
            break;
        case MRIM_CS_CONTACT_LIST2:
            loc = (MrimPktHeader*) _parse_contact_list(pkt);
            break;
        default:
            #ifdef ENABLE_MRIM_DEBUG
            purple_debug_info("mrim", "parsing unsupported type of packet %x\n", 
                (guint32) GUINT32_FROM_LE(pkt->msg));
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
                _free_message_status((MrimPktMessageStatus*) loc);
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
                _free_offline_message_ack((MrimPktOfflineMessageAck*) loc);
                break;
            case MRIM_CS_AUTHORIZE_ACK:
                _free_authorize_ack((MrimPktAuthorizeAck*) loc);
                break;
            case MRIM_CS_MPOP_SESSION:
                break;
            case MRIM_CS_ANKETA_INFO:
                _free_anketa_info((MrimPktAnketaInfo*) loc);
                break;
            case MRIM_CS_CONTACT_LIST2:
                _free_contact_list((MrimPktContactList*) loc);
                break;
            default:
                #ifdef ENABLE_MRIM_DEBUG
                purple_debug_info("mrim", "freeing unsupported type of packet %u\n", 
                    (guint32) loc->msg);
                #endif
                break;
        }
    }
}
