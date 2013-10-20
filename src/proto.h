

//***************************************************************************
// $Id: proto.h,v 1.412 2012/03/05 11:09:47 serdtcev Exp $
//***************************************************************************

#ifndef MRIM_PROTO_H
#define MRIM_PROTO_H

/************************************************************************
   Types and definitions
  ************************************************************************

WORD - unsigned short (16 bits)
DWORD - unsigned int (32 bits)
u_int - unsigned int (32 bits)
LPS - long pascal string (DWORD size | data with size 'size')
UL - unsigned long (32 bits, same as DWORD)
CLPS - complex lps (DWORD size | DWORD lps_num | LPS 0 | LPS 1 | ... | LPS
lps_num-1)
GUID - global unique id (char[16])

  ************************************************************************
   end of Types and definitions
  ************************************************************************


  ************************************************************************
   Common descriptions
  ************************************************************************

MRIM - Mail.Ru Instant Messenger, is a binary protocol designed and
developed
to carry a multitude of services about instant messaging and client-server
communications.

Logically, the protocol can be separated into PACKETS. Each packet is an
amount of data
that is transmitted over network between two endpoints. If a packet has
_CS_ part in it's name,
then it is transmitted between Client and Server (_CS_ is used for both
directions -
there is no part _SC_).

Each packet has a HEADER.

typedef struct mrim_packet_header_t
{
     u_int      magic;        // Magic( 0xDEADBEEF for _CS_ packets )
     u_int      proto;        // pversion(1, 21) for example
     u_int      seq;            // Sequence of packet is used to wait for
acknolegement in several cases
     u_int      msg;            // identifier of a packet
     u_int      dlen;         // data length of this packet
     u_int    from;            // not user, must be zero
     u_int    fromport;        // not user, must be zero
     u_char    reserved[16];    // not user, must be filled with zeroes
} __attribute__((packed))
mrim_packet_header_t;

All packets should be received asynchronously, that is, if you are waiting
for a certain
packet, it is not necessary that this very packet will come first. Some
other packet may
arrive to you from server at any moment

  ************************************************************************
   end of Common descriptions
  ************************************************************************


  ************************************************************************
   Connection to server
  ************************************************************************

1. Connect to mrim.mail.ru on ports 2042 or 443. Connection to port 443 is
desired when the client uses http-proxy and CONNECT directive

2. Read cp1251 string with ip:port of the next server to connect. After
receiving \0 disconnect

3. Connect to ip:port. Keep in mind, that if you connect to
mrim.mail.ru:443,
then you will receive ip:443, and if you connect to mrim.mail.ru:2042,
then you
will receive ip:2041 address.

4. Send MRIM_CS_HELLO packet
Receive MRIM_CS_HELLO_ACK

5. Send MRIM_CS_LOGIN2
receive MRIM_CS_LOGIN_ACK or MRIM_CS_LOGIN_REJ

6. Receive MRIM_CS_USER_INFO

7. Receive MRIM_CS_CONTACT_LIST2

8. Receive MRIM_CS_OFFLINE_MESSAGE_ACK messages
Send MRIM_CS_DELETE_OFFLINE_MESSAGE for each offline message

9. since this moment you've passed "take of" and are in "horizontal
flight".
To disconnect from server ("landing"), simply close the socket connection

  ************************************************************************
   end of Connection to server
  ************************************************************************


  ************************************************************************
   Connection packet descriptions
  ************************************************************************

MRIM_CS_HELLO has 2 parameters
DWORD ping_timeout_seconds - desired ping for the client, if omitted == 40
DWORD flags (MRIM_HELLO_FLAG_SERVER_PINGS)

MRIM_CS_HELLO_ACK returns ping period in seconds.
Ping period is a timeout, that forces the client to send MRIM_CS_PING
packet.
Be warned, that the server DOES NOT CONSIDER ANY OTHER PACKETS as PING.
Server kills the client
since he is not sending pings with a 1.5*ping_period interval

MRIM_CS_LOGIN2 carries main login info

***************************************
// LPS login (plain text example@mail.ru)
// LPS password (plain text example_password)
***************************************
// DWORD status (see MRIM_CS_USER_STATUS)
// LPS spec_status_uri (>=1.14)    (see MRIM_CS_USER_STATUS)
// LPS status_title (>=1.14, UTF-16LE) (see MRIM_CS_USER_STATUS)
// LPS status_desc (>=1.14, UTF-16LE) (see MRIM_CS_USER_STATUS)
***************************************
// UL features (>=1.14) (see MRIM_CS_USER_STATUS)
***************************************
// LPS status_user_agent (>=1.14) (see MRIM_CS_USER_STATUS)
***************************************
// LPS lang (>=1.16) (cp1251 letters like ru en uz kz ua)
// LPS ua session (>=1.20) empty
// LPS replaced ua session (>=1.20) empty
***************************************
// LPS client description (like browser user-agent, max 256 letters.
Please write your personal client description here)
***************************************
//+ statistic packet data:
    // Format (>=1.17):
    DWORD id | BYTE type | LPS value or DWORD value depending on type

MRIM_CS_LOGIN_ACK - empty. Says that login data is ok

MRIM_CS_LOGIN_REJ - you are not connected.
// LPS reason (cp1251 string. "Invalid login" - means wrong password or
login, "Access denied" -
        your account has been blocked by antispam
// [LPS data] - should be ignored

other packets are described separately below

  ************************************************************************
   end of Connection packet descriptions
  ************************************************************************



  ************************************************************************
   Common actions
  ************************************************************************

Send/receive a message.

Send MRIM_CS_MESSAGE with header.seq field set to some unique value
(increment or random id)
Wait for MRIM_CS_MESSAGE_STATUS with the same header.seq and analyze
status value

On receiving side: receive MRIM_CS_MESSAGE_ACK (server renames
MRIM_CS_MESSAGE from sender into
MRIM_CS_MESSAGE_ACK to receiver).
Send MRIM_CS_MESSAGE_RECV to server with the same msg_id as in
MRIM_CS_MESSAGE_ACK to indicate that
you've received that message. Keep in mind flag MESSAGE_FLAG_NORECV. If it
is set, DO NOT send
MRIM_CS_MESSAGE_RECV.

Receive offline message.

Offline messages come like pop3 letters (in text presentation).
Receive MRIM_CS_OFFLINE_MESSAGE_ACK.
Send MRIM_CS_DELETE_OFFLINE_MESSAGE with the same UIDL (8-byte value) as
in MRIM_CS_OFFLINE_MESSAGE_ACK.
Parse message data. The whole string comes in cp1251 coding (though it
does not contain russian letters).

Remove \r\n symbols from string

TODO

Send SMS.
äÌÑ ÏÔÐÒÁ×ËÉ SMS ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_SMS. ÷ header.seq ÄÏÌÖÎÏ
ÂÙÔØ ÕÓÔÁÎÏ×ÌÅÎÎÏ ÎÅËÏÔÏÒÏÅ ÕÎÉËÁÌØÎÏÅ ÚÎÁÞÅÎÉÅ.
÷ ÏÔ×ÅÔ ÓÅÒ×ÅÒ ÐÒÉÓÙÌÁÅÔ ÓÏÏÂÝÅÎÉÅ MRIM_CS_SMS_ACK Ï ÓÔÁÔÕÓÅ ÄÏÓÔÁ×ËÉ
ÓÏÏÂÝÅÎÉÑ ÎÁ ÓÅÒ×ÅÒ Ó ÔÅÍ ÖÅ ÚÎÁÞÅÎÉÅÍ header.seq.
ðÒÉ ÄÏÓÔÁ×ËÅ ÓÏÏÂÝÅÎÉÑ ÁÂÏÎÅÎÔÕ ÐÒÉÈÏÄÉÔ MRIM_CS_MESSAGE_ACK Ó ÆÌÁÇÏÍ
MESSAGE_SMS_DELIVERY_REPORT.
÷ ÔÅÌÅ ÓÏÏÂÝÅÎÉÑ ÓÏÄÅÒÖÉÔÓÑ ÔÅËÓÔ ÏÂ ÕÄÁÞÎÏÊ ÄÏÓÔÁ×ËÅ ÉÌÉ ÏÂ ÏÛÉÂËÅ.

Receive SMS.
SMS ÓÏÏÂÝÅÎÉÅ ÐÒÉÈÏÄÉÔ × ×ÉÄÅ MRIM_CS_MESSAGE_ACK Ó ÆÌÁÇÏÍ
MESSAGE_FLAG_SMS. ÷ ÐÏÌÅ FROM ÓÏÄÅÒÖÉÔÓÑ ÎÏÍÅÒ ÔÅÌÅÆÏÎÁ ÁÂÏÎÅÎÔÁ.

Parse contact-list.
ëÏÎÔÁËÔ ÌÉÓÔ ÐÒÉÈÏÄÉÔ ÏÔ ÓÅÒ×ÅÒÁ ÓÒÁÚÕ ÐÏÓÌÅ ÌÏÇÉÎÁ × ÓÏÏÂÝÅÎÉÉ
MRIM_CS_CONTACT_LIST2.
äÌÑ ×ÏÚÍÏÖÎÏÓÔÉ ÒÁÓÛÉÒÅÎÉÑ ÆÏÒÍÁÔÁ ËÏÎÔÁËÔ ÌÉÓÔÁ ÉÓÐÏÌØÚÕÀÔÓÑ ÍÁÓËÉ (ÐÏÌÑ
group_mask É contacts_mask).
ëÌÉÅÎÔ ÄÏÌÖÅÎ ÞÉÔÁÔØ ÉÚ×ÅÓÔÎÙÅ ÅÍÕ ÐÏÌÑ É ÐÒÏÐÕÓËÁÔØ ÎÅÉÚ×ÅÓÔÎÙÅ.
÷ ËÏÎÔÁËÔ ÌÉÓÔÅ ÓÎÁÞÁÌÁ ÉÄÕÔ ÄÁÎÎÙÅ Ï ÇÒÕÐÐÁÈ, ÚÁÔÅÍ ÄÁÎÎÙÅ Ï ËÏÎÔÁËÔÁÈ.
÷ÉÒÔÕÁÌØÎÙÅ ÇÒÕÐÐÙ (ÔÅÌÅÆÏÎÎÙÅ ËÏÎÔÁËÔÙ, ÎÅÁ×ÔÏÒÉÚÏ×ÁÎÎÙÅ, ËÏÎÆÅÒÅÎÃÉÉ,
×ÒÅÍÅÎÎÙÅ) ÎÅ ÐÒÉÓÕÔÓÔ×ÕÀÔ × ËÏÎÔÁËÔ ÌÉÓÔÅ.
ðÒÉÎÁÄÌÅÖÎÏÓÔØ ËÏÎÔÁËÔÁ Ë ÇÒÕÐÐÅ ÏÐÒÅÄÅÌÑÅÔÓÑ ÐÏ id ÇÒÕÐÐÙ (ÐÏÌÅ group_id).
äÌÑ ×ÉÒÔÕÁÌØÎÙÈ ÇÒÕÐÐ ÐÒÉÎÁÄÌÅÖÎÏÓÔØ ÏÐÒÅÄÅÌÑÅÔÓÑ ÐÏ ÆÌÁÇÁÍ.
åÓÌÉ ËÏÎÔÁËÔ ÎÅ ÐÒÉÎÁÄÌÅÖÉÔ ÎÉ Ë ÏÄÎÏÊ ×ÉÒÔÕÁÌØÎÏÊ ÇÒÕÐÐÅ É × group_id
ÕËÁÚÁÎÁ
ÎÅÉÚ×ÅÓÔÁÎÑ ÇÒÕÐÐÁ, ÔÏ ÓÞÉÔÁÅÔÓÑ ÞÔÏ ËÏÎÔÁËÔ ÐÒÉÎÁÄÌÅÖÉÔ ÇÒÕÐÐÅ Ó id 0.
ëÏÎÔÁËÔÙ Ó ÆÌÁÇÏÍ CONTACT_FLAG_REMOVED Ñ×ÌÑÀÔÓÑ ÕÄÁÌÅÎÎÙÍÉ É ÄÏÌÖÎÙ
ÉÇÎÏÒÉÒÏ×ÁÔØÓÑ.
ëÏÎÔÁËÔÙ Ó ÆÌÁÇÏÍ CONTACT_FLAG_IGNORE ÎÁÈÏÄÉÔÓÑ × ÓÐÉÓËÅ ÉÇÎÏÒÉÒÕÅÍÙÈ É
ÄÏÌÖÅÎ ÐÏËÁÚÙ×ÁÔØÓÑ × ËÏÎÔÁËÔ ÌÉÓÔÅ.
ëÏÎÔÁËÔÙ Ó ÆÌÁÇÏÍ CONTACT_FLAG_SHADOW ÂÙÌÉ ÄÏÂÁ×ÌÅÎÙ ÐÒÉ ÉÇÎÏÒÉÒÏ×ÁÎÉ É
ÐÒÉ ÕÄÁÌÅÎÉÉ ÉÚ ÓÐÉÓËÏ× ÉÇÎÏÒÉÒÕÅÍÙÈ ÄÏÌÖÎÙ ÂÙÔØ ÕÄÁÌÅÎÙ ÉÚ ËÏÎÔÁËÔ ÌÉÓÔÁ.

Add contact.
äÌÑ ÄÏÂÁ×ÌÅÎÉÑ ËÏÎÔÁËÔÁ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_ADD_CONTACT.
÷ ÏÔ×ÅÔ ÓÅÒ×ÅÒ ÐÒÉÓÙÌÁÅÔ MRIM_CS_ADD_CONTACT_ACK Ó ÒÅÚÕÌØÔÁÔÏÍ ÄÏÂÁ×ÌÅÎÉÑ
É id ËÏÎÔÁËÔÁ.
÷ ÓÌÕÞÁÅ ÄÏÂÁ×ÌÅÎÉÑ ËÏÎÆÅÒÅÎÃÉÉ × ÏÔ×ÅÔÅ ÅÝÅ ÐÒÉÈÏÄÉÔ ÎÁÚ×ÁÎÉÅ ËÏÎÆÅÒÅÎÃÉÉ.
÷ ÓÌÕÞÁÅ ÕÓÐÅÛÎÏÇÏ ÄÏÂÁ×ÌÅÎÉÑ ËÏÎÔÁËÔ ÄÏÂÁ×ÌÑÅÔÓÑ ËÁË ÎÅÁ×ÔÏÒÉÚÏ×ÁÎÎÙÊ É
ÓÅÒ×ÅÒ Á×ÔÏÍÁÔÉÞÅÓËÉ
ÏÔÐÒÁ×ÌÑÅÔ ÓÏÂÅÓÅÄÎÉËÕ ÚÁÐÒÏÓ Á×ÔÏÒÉÚÁÃÉÉ × ×ÉÄÅ MRIM_CS_MESSAGE_ACK Ó
ÆÌÁÇÏÍ MESSAGE_FLAG_AUTHORIZE.
ðÒÉ ÐÏÌÏÖÉÔÅÌØÎÏÍ ÏÔ×ÅÔÅ ÓÏÂÅÓÅÄÎÉË ÏÔÐÒÁ×ÌÑÅÔ ÐÏÄÔ×ÅÒÖÄÅÎÉÅ Á×ÔÏÒÉÚÁÃÉÉ.
äÌÑ ÜÔÏÇÏ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_AUTHORIZE.
îÁ ÓÔÏÒÏÎÅ ÐÏÌÕÞÁÔÅÌÑ Á×ÔÏÒÉÚÁÃÉÉ ÜÔÏ ÓÏÏÂÝÅÎÉÅ ÐÒÉÈÏÄÉÔ ËÁË
MRIM_CS_AUTHORIZE_ACK.


ëÌÉÅÎÔ ÍÏÖÅÔ ÓÁÍ ÏÔÐÒÁ×ÌÑÔØ ÚÁÐÒÏÓ Á×ÔÏÒÉÚÁÃÉÉ ÄÌÑ ÐÏ×ÔÏÒÎÏÇÏ ÚÁÐÒÏÓÁ
Á×ÔÏÒÉÚÁÃÉÉ Õ ÓÏÂÅÓÅÄÎÉËÁ.
äÌÑ ÜÔÏÇÏ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_MESSAGE Ó ÆÌÁÇÏÍ
MESSAGE_FLAG_AUTHORIZE.

Add phone contact.
äÌÑ ÄÏÂÁ×ÌÅÎÉÅ ÔÅÌÅÆÏÎÎÏÇÏ ËÏÎÔÁËÔÁ ÉÓÐÏÌØÚÕÅÔÓÑ MRIM_CS_ADD_CONTACT Ó
ÆÌÁÇÏÍ CONTACT_FLAG_PHONE.
÷ÍÅÓÔÏ e-mail'Á ÄÏÌÖÎÏ ÂÙÔØ ÕËÁÚÁÎÏ ÓÌÏ×Ï "phone".
÷ ÏÔ×ÅÔ ÓÅÒ×ÅÒ ÐÒÉÓÙÌÁÅÔ MRIM_CS_ADD_CONTACT_ACK Ó ÒÅÚÕÌØÔÁÔÏÍ ÄÏÂÁ×ÌÅÎÉÑ.
îÉËÁËÉÈ ÚÁÐÒÏÓÏ× Á×ÔÏÒÉÚÁÃÉÉ ÐÒÉ ÜÔÏÍ ÎÅ ÐÒÏÉÓÈÏÄÉÔ É ËÏÎÔÁËÔ ÄÏÂÁ×ÌÑÅÔÓÑ
× ËÏÎÔÁËÔ ÌÉÓÔ.


Modify contact.
ðÏÄ ÉÚÍÎÅÎÉÅÍ ËÏÎÔÁËÔÁ ÐÏÄÒÁÚÕÍÅ×ÁÀÔÓÑ ÓÌÅÄÕÀÝÉÅ ÏÐÅÒÁÃÉÉ:
- ÐÅÒÅÉÍÅÎÏ×ÁÎÉÅ;
- ÄÏÂÁ×ÌÅÎÉÅ × ÓÐÉÓÏË ÉÇÎÏÒÉÒÕÅÍÙÈ;
- ÄÏÂÁ×ÌÅÎÉÅ × ÓÐÉÓÏË "Ñ ×ÓÅÇÄÁ ÎÅ ×ÉÄÉÍ ÄÌÑ...";
- ÄÏÂÁ×ÌÅÎÉÅ × ÓÐÉÓÏË "Ñ ×ÓÅÇÄÁ ×ÉÄÉÍ ÄÌÑ...";
- ÐÅÒÅÎÏÓ × ÄÒÕÇÕÀ ÇÒÕÐÐÕ;
- ÉÚÍÅÎÅÎÉÅ ÐÏÌÏÖÅÎÉÑ ÇÒÕÐÐÙ;
- ÉÚÍÅÎÅÎÉÅ ÔÅÌÅÆÏÎÏ×
- ÕÄÁÌÅÎÉÅ.
äÌÑ ÉÚÍÅÎÅÎÉÑ ËÏÎÔÁËÔÁ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_MODIFY_CONTACT.
÷ ÏÔ×ÅÔ ÓÅÒ×ÅÒ ÐÒÉÓÙÌÁÅÔ MRIM_CS_MODIFY_CONTACT_ACK ÓÏ ÓÔÁÕÓÏÍ ÏÐÅÒÁÃÉÉ.

Delete contact.
õÄÁÌÅÎÉÅ ËÏÎÔÁËÔÁ ÐÒÏÉÓÈÏÄÉÔ ÚÁ ÓÞÅÔ ÕÓÔÁÎÏ×ËÉ ÆÌÁÇÁ CONTACT_FLAG_REMOVED.
(ÓÍ Modify Contact).
åÓÌÉ ÕÄÁÌÑÅÔÓÑ ËÏÎÔÁËÔ ÉÚ ÓÐÉÓËÁ ÉÇÎÏÒÉÒÕÅÍÙÈ, ÔÏ Õ ÎÅÇÏ ÎÕÖÎÏ ÓÎÑÔØ ÆÌÁÇ
CONTACT_FLAG_SHADOW.

Ignore contact.
åÓÌÉ ËÏÎÔÁËÔ ÕÖÅ ÎÁÈÏÄÉÔÓÑ × ËÏÎÔÁËÔ-ÌÉÓÔÅ, ÔÏ ÅÍÕ ÄÏÓÔÁÔÏÞÎÏ ÕÓÔÁÎÏ×ÉÔØ
ÆÌÁÇ CONTACT_FLAG_IGNORE (ÓÍ Modify Contact).
åÓÌÉ ËÏÎÔÁËÔ ÏÔÓÕÔÓÔ×ÕÅÔ × ËÏÎÔÁËÔ-ÌÉÓÔÅ, ÔÏ ÅÇÏ ÎÕÖÎÏ ÄÏÂÁ×ÉÔØ Ó ÆÌÁÇÁÍÉ
CONTACT_FLAG_SHADOW É CONTACT_FLAG_IGNORE (ÓÍ Add Contact).
÷ ÜÔÏÍ ÓÌÕÞÁÅ Á×ÔÏÒÉÚÁÃÉÑ ÚÁÐÒÁÛÉ×ÁÔØÓÑ ÎÅ ÂÕÄÅÔ.

Add group.
äÌÑ ÄÏÂÁ×ÌÅÎÉÑ ÇÒÕÐÐÙ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_ADD_CONTACT (ÓÍ Add
Contact).
÷ ÐÏÌÑÈ ÌÏÇÉÎÁ, ÔÅÌÅÆÏÎÏ× É ÔÅËÓÔÁ Á×ÔÏÒÉÚÁÃÉÉ ÕËÁÚÙ×ÁÅÔÓÑ ÐÕÓÔÁÑ ÓÔÒÏËÁ.
÷ ÐÏÌÅ ÆÌÁÇÏ× ÄÏÌÖÅÎ ÂÙÔØ ÆÌÁÇ CONTACT_FLAG_GROUP.
÷ ÓÔÁÒÛÅÍ ÂÁÊÔÅ ÐÏÌÑ ÆÌÁÇÏ× ÄÏÌÖÎÁ ÂÙÔØ ÕËÁÚÁÎÁ ÐÏÚÉÃÉÑ ÇÒÕÐÐÙ.

Delete group.
õÄÁÌÅÎÉÅ ÇÒÕÐÐÙ ÐÒÏÉÓÈÏÄÉÔ ÁÎÁÌÏÇÉÞÎÏ ÕÄÁÌÅÎÉÀ ËÏÎÔÁËÔÁ.
÷ ÐÏÌÑÈ ÌÏÇÉÎÁ É ÔÅÌÅÆÏÎÏ× ÕËÁÚÙ×ÁÅÔÓÑ ÐÕÓÔÁÑ ÓÔÒÏËÁ.

Rename group.
ðÅÒÅÉÍÅÎÏ×ÁÎÉÅ ÇÒÕÐÐÙ ÐÒÏÉÓÈÏÄÉÔ ÁÎÁÌÏÇÉÞÎÏ ÐÅÒÅÉÍÅÎÏ×ÁÎÉÀ ËÏÎÔÁËÔÁ (ÓÍ
Modify Contact).
÷ ÐÏÌÑÈ ÌÏÇÉÎÁ É ÔÅÌÅÆÏÎÏ× ÕËÁÚÙ×ÁÅÔÓÑ ÐÕÓÔÁÑ ÓÔÒÏËÁ.

Reorder group.
þÔÏÂÙ ÉÚÍÍÅÎÉÔØ ÐÏÌÏÖÅÎÉÅ ÇÒÕÐÐÙ, ÎÕÖÎÏ ÉÚÍÅÎÉÔØ ÎÏÍÅÒ ÐÏÚÉÃÉÉ × ÓÔÁÒÛÅÍ
ÂÁÊÔÅ ÐÏÌÑ ÆÌÁÇÏ×.
äÌÑ ÉÚÍÍÅÎÅÎÉÑ ÐÏÌÑ ÆÌÁÇÏ× ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_MODIFY_CONTACT
(ÓÍ Modify Contact).
÷ ÐÏÌÑÈ ÌÏÇÉÎÁ É ÔÅÌÅÆÏÎÏ× ÕËÁÚÙ×ÁÅÔÓÑ ÐÕÓÔÁÑ ÓÔÒÏËÁ.

Move contact.
þÔÏÂÙ ÐÅÒÅÍÅÓÔÉÔØ ËÏÎÔÁËÔ ÉÚ ÏÄÎÏÊ ÇÒÕÐÐÙ × ÄÒÕÇÕÀ ÎÕÖÎÏ ÉÚÍÅÎÉÔØ ÅÇÏ id
ÇÒÕÐÐÙ.
äÌÑ ÜÔÏÇÏ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_MODIFY_CONTACT (ÓÍ Modify
Contact).

Mail.Ru URL's
þÔÏ ÏÔËÒÙÔØ ÐÅÒÅÊÔÉ ÎÁ ÓÔÒÁÎÉÃÕ ËÁËÏÇÏ-ÌÉÂÏ ÐÒÏÅËÔÁ Mail.Ru Ó Á×ÔÏÒÉÚÁÃÉÅÊ
ÎÕÖÎÏ ÚÁÐÒÏÓÉÔØ MPOP_SESSION.
äÌÑ ÜÔÏÇÏ ÉÓÐÏÌØÚÕÅÔÓÑ ÓÏÏÂÝÅÎÉÅ MRIM_CS_GET_MPOP_SESSION. ÷ ÏÔ×ÅÔ ÎÁ ÜÔÏ
ÓÏÏÂÝÅÎÉÅ ÓÅÒ×ÅÒ ÐÒÉÓÙÌÁÅÔ MRIM_CS_GET_MPOP_SESSION_ACK Ó ËÌÀÞÏÍ (ÐÏÌÅ
session).
ó ÜÔÉÍ ËÌÀÞÏÍ ÎÁÄÏ ÐÅÒÅÊÔÉ ÎÁ URL ×ÉÄÁ:
http://swa.mail.ru:<ÐÏÒÔ ÐÏ ËÏÔÏÒÏÍÕ ÐÏÄËÌÀÞÅÎÙ Ë
ÓÅÒ×ÅÒÕ>/cgi-bin/auth?Login=<ìÏÇÉÎ>&agent=<ËÌÀÞ session>&page=<URL ÎÁ
ËÏÔÏÒÙÊ ÎÕÖÎÏ ÐÏÐÁÓÔØ>&ver=<×ÅÒÓÉÑ ËÌÉÅÎÔÁ>&agentlang=<ÑÚÙË ËÌÉÅÎÔÁ>
swa.mail.ru Á×ÔÏÍÁÔÉÞÅÓËÉ Á×ÔÏÒÉÚÕÅÔ É ÐÅÒÅÂÒÏÓÉÔ ÎÁ URL ÉÚ ÐÁÒÁÍÅÔÒÁ page

  ************************************************************************
   end of Common actions
  ************************************************************************/


#include <sys/types.h>

#define PROTO_VERSION_MAJOR     1
//#define PROTO_VERSION_MINOR     24
#define PROTO_VERSION_MINOR     21
#define PROTO_VERSION           ((((u_int)(PROTO_VERSION_MAJOR))<<16)|(u_int)(PROTO_VERSION_MINOR))
#define pversion(major, minor)  ((((major) & 0x0000FFFF) << 16)| ((minor) & 0x0000FFFF))
#define pmajor(p) (((p) & 0xFFFF0000) >>16)
#define pminor(p) ((p) & 0x0000FFFF)
#define PROTO_MAJOR(p) (((p)&0xFFFF0000)>>16)
#define PROTO_MINOR(p) ((p)&0x0000FFFF)


#ifndef _WIN32

typedef struct mrim_packet_header_t
{
     u_int      magic;        // Magic
     u_int      proto;        // ÷ÅÒÓÉÑ ÐÒÏÔÏËÏÌÁ
     u_int      seq;        // Sequence
     u_int      msg;        // ôÉÐ ÐÁËÅÔÁ
     u_int      dlen;         // äÌÉÎÁ ÄÁÎÎÙÈ
     u_int    from;        // áÄÒÅÓ ÏÔÐÒÁ×ÉÔÅÌÑ
     u_int    fromport;    // ðÏÒÔ ÏÔÐÒÁ×ÉÔÅÌÑ
     u_char    reserved[16];    // úÁÒÅÚÅÒ×ÉÒÏ×ÁÎÏ
} __attribute__((packed))
mrim_packet_header_t;

static inline mrim_packet_header_t* mrim_packet_header(void* pkt)
{
     return (mrim_packet_header_t*) pkt;
}

static inline char* mrim_packet_body(void* pkt)
{
     return (char*) pkt + sizeof(mrim_packet_header_t);
}

static inline size_t mrim_packet_body_len(void* pkt)
{
     return ((mrim_packet_header_t*) pkt)->dlen;
}

#endif

#ifdef __cplusplus
namespace mrim {
namespace protocol {
#endif

#define CS_MAGIC    0xDEADBEEF        // ëÌÉÅÎÔÓËÉÊ Magic ( C <-> S )



/***************************************************************************

        ðòïôïëïì ó÷ñúé ëìéåîô-óåò÷åò

  ***************************************************************************/

#define MRIM_CS_HELLO           0x1001  // C -> S
     // UL client's ping period
     // UL server's ping period

#define MRIM_CS_HELLO_ACK       0x1002  // S -> C
     // UL ping_period
     // UL server time sec
     // UL server time nano sec


#define MRIM_CS_LOGIN_ACK       0x1004  // S -> C
     // empty

#define MRIM_CS_LOGIN_REJ       0x1005  // S -> C
     // LPS reason
     // [LPS data]

#define MRIM_CS_PING            0x1006  // C -> S
     // empty

#define MRIM_CS_MESSAGE            0x1008  // C -> S
    // UL flags
    // LPS to
    // LPS message (CP-1251, UTF-16LE)
    // LPS rtf-formatted message (>=1.1)
         // [ LPS multichat_data ] (>= 1.20)
             // UL type
             // switch(type) {
             //   MULTICHAT_ADD_MEMBERS {
             //     CLPS members
             //   }
             //   MULTICHAT_DEL_MEMBERS {
             //     CLPS members
             //   }
             // }

    #define MESSAGE_FLAG_OFFLINE        0x00000001 // only from server to client
    #define MESSAGE_FLAG_NORECV        0x00000004
    #define MESSAGE_FLAG_AUTHORIZE        0x00000008
    #define MESSAGE_FLAG_SYSTEM        0x00000040
    #define MESSAGE_FLAG_RTF        0x00000080
    #define MESSAGE_FLAG_CONTACT        0x00000200
    #define MESSAGE_FLAG_NOTIFY        0x00000400
    #define MESSAGE_FLAG_SMS        0x00000800 // only from server to client
    #define MESSAGE_FLAG_MULTICAST        0x00001000
    #define MESSAGE_SMS_DELIVERY_REPORT    0x00002000 // only from server to client
    #define MESSAGE_FLAG_WAKEUP        0x00004000
    #define MESSAGE_FLAG_FLASH        0x00008000
    #define MESSAGE_FLAG_SPAM               0x00010000
    #define MESSAGE_FLAG_CP1251         0x00200000
    #define MESSAGE_FLAG_MULTICHAT      0x00400000
    #define MESSAGE_FLAG_STATISTIC_OF   0x00800000
    #define MESSAGE_FLAG_VIDEOMISS        0x01000000
    #define MESSAGE_FLAG_VOICEMISS        0x02000000

         #define MULTICHAT_MESSAGE           0 //chat messages (rtf, mults, wakeup, typing notification)
         #define MULTICHAT_GET_MEMBERS       1 //ask for members list
         #define MULTICHAT_MEMBERS           2 //list of chat members arrived
         #define MULTICHAT_ADD_MEMBERS       3 //someone has added some users to chat
         #define MULTICHAT_ATTACHED          4 //is not sent. should be sent when user adds multichat contact to his contact list
         #define MULTICHAT_DETACHED          5 //someone has left the chat himself (he was not deleted by another person)
         #define MULTICHAT_DESTROYED         6 //is sent when the "totalitary" multichat is destroyed
         #define MULTICHAT_INVITE            7 //someone has invited me to chat
         #define MULTICHAT_DEL_MEMBERS       8 //someone has deleted some users from chat
         #define MULTICHAT_TURN_OUT          9 //someone has delete me from chat
    
#define MAX_MULTICAST_RECIPIENTS 50 // Flags that user is allowed to set himself.
#define MESSAGE_USERFLAGS_MASK \
     ( \
         MESSAGE_FLAG_NORECV | \
         MESSAGE_FLAG_AUTHORIZE | \
         MESSAGE_FLAG_URL | \
         MESSAGE_FLAG_SYSTEM | \
         MESSAGE_FLAG_RTF | \
         MESSAGE_FLAG_CONTACT | \
         MESSAGE_FLAG_NOTIFY | \
         MESSAGE_FLAG_MULTICAST | \
         MESSAGE_FLAG_WAKEUP | \
         MESSAGE_FLAG_FLASH | \
         MESSAGE_FLAG_SPAM | \
         MESSAGE_FLAG_MYMAIL_INVITE | \
         MESSAGE_FLAG_CP1251 | \
         MESSAGE_FLAG_MULTICHAT | \
         MESSAGE_FLAG_VIDEOMISS | \
         MESSAGE_FLAG_VOICEMISS \
     )

#define MRIM_CS_MESSAGE_ACK        0x1009  // S -> C
    // UL msg_id
    // UL flags
    // LPS from
    // LPS message (CP-1251, UTF-16LE)
    // LPS rtf-formatted message (>=1.1)
         // [ LPS miltichat_data ] (>= 1.20)
             // UL type
             // LPS multichat_name
             // switch(type) {
             //   MULTICHAT_MESSAGE {
             //     LPS sender
             //   }
             //   MULTICHAT_MEMBERS {
             //     CLPS members
             //     [ LPS owner ]
             //   }
             //   MULTICHAT_ADD_MEMBERS {
             //     LPS sender
             //     CLPS members
             //   }
             //   MULTICHAT_ATTACHED {
             //     LPS member
             //   }
             //   MULTICHAT_DETACHED {
             //     LPS member
             //   }
             //   MULTICHAT_INVITE {
             //     LPS sender
             //   }
             //   MULTICHAT_DEL_MEMBERS {
             //     LPS sender
             //     CLPS members
             //   }
             //   MULTICHAT_TURN_OUT {
             //     LPS by
             //   }
             // }
         // [ U64 archId ]

    
#define MRIM_CS_MESSAGE_RECV    0x1011    // C -> S
    // LPS from
    // UL msg_id

#define MRIM_CS_MESSAGE_STATUS    0x1012    // S -> C
    // UL status
    #define MESSAGE_DELIVERED        0x0000    // Message delivered directly to user
    #define MESSAGE_REJECTED_NOUSER        0x8001  // Message rejected - no such user
    #define MESSAGE_REJECTED_INTERR        0x8003    // Internal server error
    #define MESSAGE_REJECTED_LIMIT_EXCEEDED    0x8004    // Offline messages limit exceeded
    #define MESSAGE_REJECTED_TOO_LARGE    0x8005    // Message is too large
         #define MESSAGE_REJECTED_RESTRICT_OFFMSG    0x8007 // for WAKEUP and FLASH to offline user
         #define MESSAGE_REJECTED_PERMISSION    0x8008
         #define MESSAGE_REJECTED_LIMIT          0x8009

#define MRIM_CS_USER_STATUS    0x100F    // S -> C
    // UL status
         // LPS spec_status_uri (>=1.14)
             #define SPEC_STATUS_URI_MAX 256
         // LPS status_title (>=1.14, UTF-16LE)
             #define STATUS_TITLE_MAX 32
         // LPS status_desc (>=1.14, UTF-16LE)
             #define STATUS_DESC_MAX 128
    #define STATUS_OFFLINE        0x00000000
    #define STATUS_ONLINE        0x00000001
    #define STATUS_AWAY        0x00000002
    #define STATUS_UNDETERMINATED    0x00000003
         #define STATUS_USER_DEFINED     0x00000004
    #define STATUS_FLAG_INVISIBLE    0x80000000
    // LPS user
         // UL features (>=1.14)
             #define FEATURE_FLAG_RTF_MESSAGE       0x00000001
             #define FEATURE_FLAG_BASE_SMILES       0x00000002
             #define FEATURE_FLAG_ADVANCED_SMILES   0x00000004
             #define FEATURE_FLAG_CONTACTS_EXCH     0x00000008
             #define FEATURE_FLAG_WAKEUP            0x00000010
             #define FEATURE_FLAG_MULTS             0x00000020
             #define FEATURE_FLAG_FILE_TRANSFER     0x00000040
             #define FEATURE_FLAG_VOICE             0x00000080
             #define FEATURE_FLAG_VIDEO             0x00000100
             #define FEATURE_FLAG_GAMES             0x00000200
             #define FEATURE_FLAG_ENABLE_VIDEO_CAMERA    0x00000400
             #define FEATURE_FLAG_WEBRTC             0x00000800
             #define FEATURE_FLAG_GOOBER             0x00001000
             #define FEATURE_FLAG_TRANSCODING_SUPPORTED 0x00002000
             #define FEATURE_FLAG_WEB_CALL           0x00004000  // Speex fix
             #define FEATURE_FLAG_LAST               FEATURE_FLAG_WEB_CALL
             #define FEATURE_UA_FLAG_MASK           ((FEATURE_FLAG_LAST <<1) - 1)  // LPS user_agent (>=1.14)
             #define USER_AGENT_MAX 255
             // Format:
             //  user_agent       = param *(param )
             //  param            = pname "=" pvalue
             //  pname            = token
             //  pvalue           = token / quoted-string
             //
             // Params:
             //  "name" - sys-name.
             //  "title" - display-name.
             //  "version" - product internal numeration. Examples: "1.2","1.3 pre".
             //  "build" - product internal numeration (may be positive number or time).
             //  "protocol" - MMP protocol number by format "<major>.<minor>".

#define MRIM_CS_LOGOUT            0x1013    // S -> C
    // UL reason
    #define LOGOUT_NO_RELOGIN_FLAG    0x0010        // Logout due to double login
         #define LOGOUT_BY_ANTISPAM      0x0020
    
#define MRIM_CS_CONNECTION_PARAMS    0x1014    // S -> C
    // UL ping_period

#define MRIM_CS_USER_INFO            0x1015    // S -> C
    // (LPS key, LPS value)* X (UTF-16LE)
             // HAS_MYMAIL (empty value)
               
#define MRIM_CS_ADD_CONTACT            0x1019    // C -> S
    // UL flags (group(2) or usual(0)
    // UL group id (unused if contact is group)
    // LPS contact  // "phone" for phone contact
    // LPS name (UTF-16LE)
    // LPS phone
    // LPS message
         // UL actions ( >= 1.15)
         // [LPS multichat_data]
             // CLPS members (>= 1.20)
             // [ LPS owner ]
    #define CONTACT_FLAG_REMOVED        0x00000001
    #define CONTACT_FLAG_GROUP        0x00000002
    #define CONTACT_FLAG_INVISIBLE        0x00000004
    #define CONTACT_FLAG_VISIBLE        0x00000008
    #define CONTACT_FLAG_IGNORE        0x00000010
    #define CONTACT_FLAG_SHADOW        0x00000020
         #define CONTACT_FLAG_AUTHORIZED         0x00000040
         #define CONTACT_FLAG_MULTICHAT          0x00000080
    #define CONTACT_FLAG_PHONE              0x00100000
         #define CONTACT_FLAG_UNICODE_NAME       0x00000200

         #define ADD_CONTACT_FLAG_MYMAIL_INVITE      0x00000001
         #define ADD_CONTACT_FLAG_MULTICHAT_ATTACHE  0x00000002
    
#define MRIM_CS_ADD_CONTACT_ACK            0x101A    // S -> C
    // UL status
    // UL contact_id or (u_int)-1 if status is not OK
         // [LPS multichat_contact (>= 1.20)]
    
    #define CONTACT_OPER_SUCCESS        0x0000
    #define CONTACT_OPER_ERROR        0x0001
    #define CONTACT_OPER_INTERR        0x0002
    #define CONTACT_OPER_NO_SUCH_USER    0x0003
    #define CONTACT_OPER_INVALID_INFO    0x0004
    #define CONTACT_OPER_USER_EXISTS    0x0005
    #define CONTACT_OPER_GROUP_LIMIT    0x6
    
#define MRIM_CS_MODIFY_CONTACT            0x101B    // C -> S, S -> C
    // UL id
    // UL flags - same as for MRIM_CS_ADD_CONTACT
    // UL group id (unused if contact is group)
    // LPS contact
    // LPS name (UTF-16LE)
    // lps phone
    
#define MRIM_CS_MODIFY_CONTACT_ACK        0x101C    // S -> C
    // UL status, same as for MRIM_CS_ADD_CONTACT_ACK

#define MRIM_CS_OFFLINE_MESSAGE_ACK        0x101D    // S -> C
    // UIDL
    // LPS offline message

#define MRIM_CS_DELETE_OFFLINE_MESSAGE        0x101E    // C -> S
    // UIDL

    
#define MRIM_CS_AUTHORIZE            0x1020    // C -> S
    // LPS user
    
#define MRIM_CS_AUTHORIZE_ACK            0x1021    // S -> C
    // LPS user

#define MRIM_CS_CHANGE_STATUS            0x1022    // C -> S, S -> C
    // UL new status
         // LPS spec_status_uri (>=1.14)
         // LPS status_title (>=1.14, UTF-16LE)
         // LPS status_desc (>=1.14, UTF-16LE)
         // UL features (>=1.14) (see MRIM_CS_USER_STATUS)


#define MRIM_CS_GET_MPOP_SESSION        0x1024    // C -> S
    
    
#define MRIM_CS_MPOP_SESSION            0x1025    // S -> C
    #define MRIM_GET_SESSION_FAIL        0
    #define MRIM_GET_SESSION_SUCCESS    1
    //UL status
    // LPS mpop session

#define MRIM_CS_FILE_TRANSFER            0x1026  // C->S
    //LPS TO/FROM
    //DWORD id_request - uniq per connect
    //DWORD FILESIZE
    //LPS:  //FILENAME
        //DESCRIPTION
        //IP:PORT,IP:PORT
#define MRIM_CS_FILE_TRANSFER_ACK        0x1027 // S->C
    //DWORD status
    #define FILE_TRANSFER_STATUS_OK            1
    #define FILE_TRANSFER_STATUS_DECLINE        0
    #define FILE_TRANSFER_STATUS_ERROR        2
    #define FILE_TRANSFER_STATUS_INCOMPATIBLE_VERS    3
    #define FILE_TRANSFER_MIRROR            4

#define FILE_ENDSTATUS_LIST {FILE_TRANSFER_STATUS_DECLINE,FILE_TRANSFER_STATUS_ERROR}
    //LPS TO/FROM
    //DWORD id_request
    //LPS DESCRIPTION
         //LPS user_data_2 (>=1.16)

//white pages!
#define MRIM_CS_WP_REQUEST            0x1029 //C->S
//DWORD field, LPS value (UTF-16LE)
#define PARAMS_NUMBER_LIMIT            50
#define PARAM_VALUE_LENGTH_LIMIT        64

#ifdef __cplusplus
} // namespace protocol
} // namespace mrim
#endif
//if last symbol in value eq '*' it will be replaced by LIKE '%'
// params define
// must be  in consecutive order (0..N) to quick check in check_anketa_info_request
enum {
   MRIM_CS_WP_REQUEST_PARAM_USER        = 0,
   MRIM_CS_WP_REQUEST_PARAM_DOMAIN,       
   MRIM_CS_WP_REQUEST_PARAM_NICKNAME,            // (UTF-16LE)
   MRIM_CS_WP_REQUEST_PARAM_FIRSTNAME,           // (UTF-16LE)
   MRIM_CS_WP_REQUEST_PARAM_LASTNAME,            // (UTF-16LE)
   MRIM_CS_WP_REQUEST_PARAM_SEX    ,   
   MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY,   
   MRIM_CS_WP_REQUEST_PARAM_DATE1    ,   
   MRIM_CS_WP_REQUEST_PARAM_DATE2    ,   
   //!!!!!!!!!!!!!!!!!!!online request param must be at end of request!!!!!!!!!!!!!!!
   MRIM_CS_WP_REQUEST_PARAM_ONLINE    ,   
   MRIM_CS_WP_REQUEST_PARAM_STATUS    ,     // we do not used it, yet
   MRIM_CS_WP_REQUEST_PARAM_CITY_ID,   
   MRIM_CS_WP_REQUEST_PARAM_ZODIAC,       
   MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_MONTH,   
   MRIM_CS_WP_REQUEST_PARAM_BIRTHDAY_DAY,   
   MRIM_CS_WP_REQUEST_PARAM_COUNTRY_ID,   
   MRIM_CS_WP_REQUEST_PARAM_CAMERA = 17,
   MRIM_CS_WP_REQUEST_PARAM_DATING = 18,
};
#ifdef __cplusplus
namespace mrim {
namespace protocol {
#endif

#define MRIM_CS_ANKETA_INFO            0x1028 //S->C
//DWORD status
    #define MRIM_ANKETA_INFO_STATUS_OK        1
    #define MRIM_ANKETA_INFO_STATUS_NOUSER        0
    #define MRIM_ANKETA_INFO_STATUS_DBERR        2
    #define MRIM_ANKETA_INFO_STATUS_RATELIMERR    3
//DWORD fields_num               
//DWORD max_rows
//DWORD server_time sec since 1970 (unixtime)
// fields set                 //%fields_num == 0
//values set                 //%fields_num == 0
//LPS value (numbers too, UTF-16LE)

#define MRIM_CS_TALK_ACK            0x1032
//DWORD status
    #define TALK_STATUS_OK 1
    #define TALK_STATUS_DECLINE 0
    #define TALK_STATUS_ERROR 2
    #define TALK_STATUS_INCOMPATIBLE_VERS 3
    #define TALK_STATUS_NOHARDWARE 4
    #define TALK_STATUS_MIRROR 5

#define TALK_ENDSTATUS_LIST {TALK_STATUS_DECLINE, TALK_STATUS_ERROR,TALK_STATUS_NOHARDWARE}
//LPS TO/FROM
//DWORD id_request
//LPS:    //WAVEFORMAT
    //DESCRIPTION
    
#define MRIM_CS_MAILBOX_STATUS            0x1033   
//DWORD new messages in mailbox

#define MRIM_CS_GAME            0x1035
//
//LPS to/from
//DWORD session //unique per game
//DWORD msg //internal game message
#define MRIM_GAME_SEA_BATTLE_GUID "\x5b\x3a\x9c\xfa\xa7\x62\xf5\x4c\xb8\x3a\x37\xa3\x32\x46\x58\x28"
//DWORD msg_id //id for ack
//DWORD time_send //time of client
//LPS data

#ifdef __cplusplus
} // namespace protocol
} // namespace mrim
#endif
enum {
   GAME_BASE,
   GAME_CONNECTION_INVITE,
   GAME_CONNECTION_ACCEPT,
   GAME_DECLINE,
   GAME_INC_VERSION,
   GAME_NO_SUCH_GAME,
   GAME_JOIN,
   GAME_CLOSE,
   GAME_SPEED,
   GAME_SYNCHRONIZATION,
   GAME_USER_NOT_FOUND,
   GAME_ACCEPT_ACK,
   GAME_PING,
   GAME_RESULT,
   GAME_MESSAGES_NUMBER
};
#ifdef __cplusplus
namespace mrim {
namespace protocol {
#endif

#define MRIM_CS_CONTACT_LIST2        0x1037 //S->C
// UL status
#define GET_CONTACTS_OK            0x0000
#define GET_CONTACTS_ERROR        0x0001
#define GET_CONTACTS_INTERR        0x0002
//DWORD status  - if ...OK than this staff:
//DWORD groups number
//mask symbols table:
//'s' - lps
//'u' - unsigned int
//'z' - zero terminated string
//LPS groups fields mask
//LPS contacts fields mask
//group fields
//contacts fields
//groups mask 'us' == flags, name
//contact mask 'uussuussssus' flags, group_id, email, nickname (UTF-16LE), internal flags, status, phone,
//spec_status_uri, status_title (UTF-16LE), status_desc (UTF-16LE),features, user_agent
    #define CONTACT_INTFLAG_NOT_AUTHORIZED    0x0001


//old packet cs_login with cs_statistic
#define MRIM_CS_LOGIN2           0x1038  // C -> S
#define MAX_CLIENT_DESCRIPTION 1024
// LPS login
// LPS password
// DWORD status
// LPS spec_status_uri (>=1.14)
// LPS status_title (>=1.14, UTF-16LE)
// LPS status_desc (>=1.14, UTF-16LE)
// UL features (>=1.14) (see MRIM_CS_USER_STATUS)
// LPS user_agent (>=1.14) (see MRIM_CS_USER_STATUS)
// LPS lang (>=1.16)
// LPS ua session (>=1.20)
// LPS replaced ua session (>=1.20)
// LPS client description //max 256
//+ statistic packet data:
     // Format (>=1.17):
     // DWORD id
         #define MRIM_STAT_BUILD                         0
         #define MRIM_STAT_LOGIN_CNT                     1
         #define MRIM_STAT_STC                           2
         #define MRIM_STAT_ID                            3
         #define MRIM_STAT_SET_AUTORUN                   4
         #define MRIM_STAT_SET_MAIL_NOTIFY               5
         #define MRIM_STAT_SET_ANTISPAM_TYPE             6
         #define MRIM_STAT_SET_TABS                      7
         #define MRIM_STAT_WINDOW_OPENINGS               8
     // BYTE  type
         #define MRIM_STAT_TYPE_LPS 1
         #define MRIM_STAT_TYPE_DW  2
         #define MRIM_STAT_TYPE_STATISTIC_PACKET  3
     // <type> data

/**
    this is an incoming sms packet, which goes from agent application
  */
#define MRIM_CS_SMS 0x1039
//32bit flags
//LPS phone
//LPS message (UTF-16LE)

/**
this message is a report message from server to client
  */
#define MRIM_CS_SMS_ACK 0x1040 //S->C
//32 bit delivery status
    #define SMS_ACK_DELIVERY_STATUS_SUCCESS 1
    #define SMS_ACK_SERVICE_UNAVAILABLE 2
    #define SMS_ACK_DELIVERY_STATUS_INVALID_PARAMS 0x10000

#define MRIM_CS_LOOKUP_USER_BY_ID    0x1042 //C->S
// http://www.mail.ru/agent?message&ids=
//DWORD n
//LPS "CRC32(USERNAME)USERID" x N

#define MAX_LOOKUP_BY_ID 10
#define MRIM_CS_LOOKUP_USER_BY_ID_MAX_N    10

#define MRIM_CS_LOOKUP_USER_BY_ID_ANSWER 0x1043 // S->C
enum MRIM_CS_LOOKUP_USER_BY_ID_ANSWER_STATUS {
   MRIM_CS_LOOKUP_USER_BY_ID_ANSWER_STATUS_ERROR = 0,
   MRIM_CS_LOOKUP_USER_BY_ID_ANSWER_STATUS_SUCCESS
};
//DWORD status
//DWORD N
//LPS email1,LPS email2... , LPS emailN

#ifdef __cplusplus
} // namespace protocol
} // namespace mrim
#endif

#ifdef __cplusplus
namespace mrim {
namespace protocol {
#endif

#define MRIM_CS_PROXY            0x1044
// LPS         to
// DWORD     id_request
// DWORD    data_type
    #define MRIM_PROXY_TYPE_VOICE                1
    #define MRIM_PROXY_TYPE_FILES                2
    #define MRIM_PROXY_TYPE_PHONE                3
    #define MRIM_PROXY_TYPE_VIDEO                4
    #define MRIM_PROXY_TYPE_UDP_VOICE            5
    #define MRIM_PROXY_TYPE_UDP_VIDEO            6
    #define MRIM_PROXY_TYPE_UDP_PHONE            7
    #define MRIM_PROXY_TYPE_WEBRTC                8
        #define MRIM_WEBRTC_TYPE_AUDIO                    1
        #define MRIM_WEBRTC_TYPE_VIDEO                    2
        #define MRIM_WEBRTC_TYPE_SIGNALLING_JSON        3
        #define MRIM_WEBRTC_TYPE_ADD_VIDEO                4
    #define MRIM_PROXY_TYPE_WEBRTC_PHONE            9
// LPS          user_data
// LPS        lps_ip_port
// DWORD    session_id[4]
// LPS          user_data_2 (>=1.16)


#define MRIM_CS_PROXY_ACK        0x1045
//DWORD     status
#define PROXY_STATUS_OK 1
#define PROXY_STATUS_DECLINE 0
#define PROXY_STATUS_ERROR 2
#define PROXY_STATUS_INCOMPATIBLE_VERS 3
#define PROXY_STATUS_NOHARDWARE 4
#define PROXY_STATUS_MIRROR 5
#define PROXY_STATUS_CLOSED 6
#define PROXY_STATUS_CHANGE_PROTOCOL 7
#define PROXY_STATUS_BUSY 8

#define PROXY_ENDSTATUS_LIST {PROXY_STATUS_DECLINE, PROXY_STATUS_ERROR, \
                               PROXY_STATUS_NOHARDWARE, PROXY_STATUS_CLOSED}

//LPS         TO
//DWORD     id_request
//DWORD     data_type
//LPS           user_data
//LPS:        lps_ip_port
//DWORD[4]     Session_id
//LPS           user_data_2 (>=1.16)

#define MRIM_CS_MAILBOX_STATUS_2     0x1048
//DWORD        n
//LPS        From
//LPS        Subject
//char        id[8]


#define MRIM_CS_TALK2                0x1049
//LPS TO/FROM
//DWORD id_request - uniq per connect
//LPS: IP:PORT,IP:PORT


//-------------------------------------------------//
//UA data names
//geo-list
/*
geo visibility list in xml

<r>
<visible>
<u email="mak@mail.ru"/>
<u email="mak1@mail.ru"/>
<u email="mak2@mail.ru"/>
..
</visible>
</r>

*/

//apple-token
/*LPS UTF16LE string*/

//-------------------------------------------------//

#define MRIM_CS_GET_UA_DATA             0x1053 // C -> S
// LPS name
     #define UA_DATA_NAME_MAX 64

#define MRIM_CS_UA_DATA                 0x1054 // S -> C
// LPS name
// LPS value

#define MRIM_CS_PUT_UA_DATA             0x1055 // C -> S
// LPS name
// LPS value
     #define UA_DATA_VAL_MAX 65536

#define MRIM_CS_PUT_UA_DATA_STATUS      0x1056 // S -> C
// DWORD status
     #define PUT_UA_DATA_OK          0
     #define PUT_UA_DATA_INTERR      1
     #define PUT_UA_DATA_NAMETOOLONG 2
     #define PUT_UA_DATA_BIGVAL      3
     #define PUT_UA_DATA_LIMIT       4
     #define PUT_UA_DATA_RATELIMIT   5

#define MRIM_CS_UDP_MEDIA           0x1059 // C -> S -> C
// LPS to/from (C -> S / S -> C)
// DWORD id_request
// DWORD type
//    #define MRIM_PROXY_TYPE_UDP_VOICE            5
//    #define MRIM_PROXY_TYPE_UDP_VIDEO            6
//    #define MRIM_PROXY_TYPE_WEBRTC                8
//        #define MRIM_WEBRTC_TYPE_AUDIO                    1
//        #define MRIM_WEBRTC_TYPE_VIDEO                    2
//        #define MRIM_WEBRTC_TYPE_SIGNALLING_JSON        3
//        #define MRIM_WEBRTC_TYPE_ADD_VIDEO                4
/*    LPS(DWORD lps_num,
        if (type MRIM_PROXY_TYPE_UDP_VOICE || MRIM_PROXY_TYPE_UDP_VIDEO)
        {
            LPS(IP:PORT,IP:PORT,...),
            LPS(IP_EXTERNAL:PORT,IP_EXTERNAL:PORT,...)
            LPS(guidSession)
            LPS(dwVersion)
        }
        else if (type MRIM_PROXY_TYPE_WEBRTC)
        {
            LPS(dwVersion)
            LPS(guidSession)
            LPS(subtype)
            LPS(json) if (subtype == MRIM_WEBRTC_TYPE_SIGNALLING_JSON)
            CLPS from MRIM_CS_VOIP_SERVERS if (subtype == MRIM_WEBRTC_TYPE_AUDIO || MRIM_WEBRTC_TYPE_VIDEO)

            //if conference 2 LPSs are added for subtype == MRIM_WEBRTC_TYPE_AUDIO || MRIM_WEBRTC_TYPE_VIDEO:
            LPS(guidConference)
            LPS(members) //"email1;email2;email3;...emailN" sorted in ascending order
        }
    )
*/

#define MRIM_CS_UDP_MEDIA_ACK       0x1060 // S -> C, C -> S -> C
// LPS to/from (C -> S / S -> C)
// DWORD status (see MRIM_CS_PROXY_ACK)
    // #define PROXY_STATUS_OK 1
    // #define PROXY_STATUS_DECLINE 0
    // #define PROXY_STATUS_ERROR 2
    // #define PROXY_STATUS_INCOMPATIBLE_VERS 3
    // #define PROXY_STATUS_NOHARDWARE 4
    // #define PROXY_STATUS_MIRROR 5
    // #define PROXY_STATUS_CLOSED 6
    // #define PROXY_STATUS_CHANGE_PROTOCOL 7
    // #define PROXY_STATUS_BUSY 8
#define MEDIA_ENDSTATUS_LIST {PROXY_STATUS_DECLINE, PROXY_STATUS_ERROR,\
                               PROXY_STATUS_NOHARDWARE, PROXY_STATUS_CLOSED}

// DWORD id_request
// DWORD type
//    #define MRIM_PROXY_TYPE_UDP_VOICE            5
//    #define MRIM_PROXY_TYPE_UDP_VIDEO            6
//    #define MRIM_PROXY_TYPE_WEBRTC                8
//        #define MRIM_WEBRTC_TYPE_AUDIO                    1
//        #define MRIM_WEBRTC_TYPE_VIDEO                    2
//        #define MRIM_WEBRTC_TYPE_SIGNALLING_JSON        3
//        #define MRIM_WEBRTC_TYPE_ADD_VIDEO                4
/*    LPS(DWORD lps_num,
        if (type MRIM_PROXY_TYPE_UDP_VOICE || MRIM_PROXY_TYPE_UDP_VIDEO)
        {
            LPS(IP:PORT,IP:PORT,...),
            LPS(IP_EXTERNAL:PORT,IP_EXTERNAL:PORT,...)
            LPS(guidSession)
            LPS(dwVersion)
        }
        else if (type MRIM_PROXY_TYPE_WEBRTC)
        {
            LPS(dwVersion)
            LPS(guidSession)
            LPS(dwSubType)
            LPS(json) if (subtype == MRIM_WEBRTC_TYPE_SIGNALLING_JSON)
            CLPS from MRIM_CS_VOIP_SERVERS if (subtype == MRIM_WEBRTC_TYPE_AUDIO || MRIM_WEBRTC_TYPE_VIDEO)

            //if conference 2 LPSs are added for subtype == MRIM_WEBRTC_TYPE_AUDIO || MRIM_WEBRTC_TYPE_VIDEO:
            LPS(guidConference)
            LPS(members) //"email1;email2;email3;...emailN" sorted in ascending order
        }
    )
*/

#define MRIM_CS_CLIENT_ACTION       0x1061 // S -> C (>= 1.19)
// DWORD codepage flags (MESSAGE_FLAG_CP1251 || 0 if unicode UTF-16LE is sent)
// LPS action (param="value" param = "value" ....)
//actions: open_msg_wnd=1 open_msg_auth=1 open_phone=1 call_phone=1 call_pc2pc_video=1 call_pc2pc_voice=1 paste_text="plain text"
//

#define MRIM_CS_DISCONNECT          0x1062 // C -> S (>=1.19)

#define MRIM_CS_USER_BLOG_STATUS    0x1063
     // DWORD flags
         #define MRIM_BLOG_STATUS_UPDATE                    0x00000001
         #define MRIM_BLOG_STATUS_MUSIC                    0x00000002
         #define MRIM_BLOG_STATUS_REPLY                    0x00000004
        #define MRIM_BLOG_STATUS_GEO                    0x00000008
        #define MRIM_BLOG_STATUS_NOTIFY                    0x00000010
        #define MRIM_BLOG_STATUS_NO_POSTING_TO_ODKL        0x00000020
     // LPS user
     // UINT64 id
     // DWORD time
     // LPS text (MRIM_BLOG_STATUS_MUSIC: track)
     // LPS reply_user_nick
     // LPS xml

#define MRIM_CS_CHANGE_USER_BLOG_STATUS  0x1064
     // DWORD flags
     // LPS text (MRIM_BLOG_STATUS_MUSIC: track)
         #define MICBLOG_STATUS_MAX 1000
     // switch(flags) {
     // MRIM_BLOG_STATUS_REPLY:
     //      UINT64 orig_id
     // }

#define MRIM_CS_LOGIN_COOKIE        0x1072
// See MRIM_CS_LOGIN2 1.20

#define MRIM_CS_MAIL_DELETED        0x1073
     // UIDL uidl

#define MRIM_CS_MAIL_READED         0x1074
     // UIDL uidl

#define MRIM_CS_SET_USER_EXT_STATUS     0x1075 // C -> S
     // DWORD flags
         #define EXT_STATUS_FLAG_SEARCHABLE  0x0001
     // CLPS to
         #define EXT_STATUS_TO_MAX 1000
     // LPS type
         #define EXT_STATUS_TYPE_MAX 64
     // LPS status
         #define EXT_STATUS_MAX 1024

#define MRIM_CS_CLEAR_USER_EXT_STATUS   0x1076 // C -> S
     // CLPS to
     // LPS type

#define MRIM_CS_USER_EXT_STATUS         0x1077 // S -> C
     // LPS from
     // CLPS list
         // LPS type
         // LPS status

#define MRIM_CS_LOGIN3                   0x1078  // C -> S
// LPS login
// LPS password
// UL features
// LPS user_agent
// LPS lang
// CLPS ua_data_names
     #define MRIM_CS_LOGIN3_UA_DATA_MAX  10
// LPS client description
// statistic packet data

#define MRIM_CS_USER_SETTINGS           0x1079  // S -> C
// CLPS list
//   LPS name (ASCII string)
//   LPS value (UTF-16LE string)

#define MRIM_CS_GET_USER_SETTINGS       0x1080  // C -> S
// CLPS
//   LPS name (ASCII string)
     #define GET_USER_SETTINGS_MAX   10
     #define USER_SETTING_NAME_MAX   64
     #define USER_SETTING_VAL_MAX    1024

#define MRIM_CS_GET_USER_SETTINGS_ERROR 0x1081  // S -> C
// UL status
     #define GET_USER_SETTINGS_INTERR        1
     #define GET_USER_SETTINGS_TOOMANY       2
     #define GET_USER_SETTINGS_NAMETOOLONG   3
     #define GET_USER_SETTINGS_BIGVAL        4
     #define GET_USER_SETTINGS_NOACCESS      5
     #define GET_USER_SETTINGS_RATELIMIT     6
// [ LPS name ]

#define MRIM_CS_SET_USER_SETTINGS       0x1082  // C -> S
// CLPS list
//   LPS name (ASCII string)
//   LPS value (UTF-16LE string)

#define MRIM_CS_SET_USER_SETTINGS_STATUS 0x1083  // S -> C
// UL status
     #define SET_USER_SETTINGS_OK            0
     #define SET_USER_SETTINGS_INTERR        1
     #define SET_USER_SETTINGS_TOOMANY       2
     #define SET_USER_SETTINGS_NAMETOOLONG   3
     #define SET_USER_SETTINGS_BIGVAL        4
     #define SET_USER_SETTINGS_NOACCESS      5
     #define SET_USER_SETTINGS_RATELIMIT     6
// [ LPS name ]

#define MRIM_GEO_APPLY_UPON_AUTO        0x1
#define MRIM_GEO_APPLY_UPON_MANUAL        0x2
#define MRIM_GEO_ALERT                    0x4

#define MRIM_CS_STARTTLS                0x1086  // C -> S, S -> C

#define MRIM_CS_OK                      0x1087  // C -> S, S -> C

#define MRIM_CS_FAILURE                 0x1088  // C -> S, S -> C
// UL code
     #define MRIM_ERR_DECLINE            1
         #define MRIM_ERR_DECLINE_STR "Decline"
     #define MRIM_ERR_NOENT              2
         #define MRIM_ERR_NOENT_STR "No such entry"
     #define MRIM_ERR_INVVAL             3
         #define MRIM_ERR_INVVAL_STR "Invalid argument"
     #define MRIM_ERR_ACCESS             4
         #define MRIM_ERR_ACCESS_STR "Permission denied"
     #define MRIM_ERR_SERVICE_UNAVAIBLABLE 5
         #define MRIM_ERR_SERVICE_UNAVAIBLABLE_STR "Service unavailable"
     #define MRIM_ERR_TIMEDOUT           6
         #define MRIM_ERR_TIMEDOUT_STR "Request timed out"
     #define MRIM_ERR_RATE_LIMIT         7
         #define MRIM_ERR_RATE_LIMIT_STR "Rate limit exceeded"
// LPS reason
// UL   failed_method

#define MRIM_CS_COMPRESS_SERVER_STREAM  0x1089
// UL method
     #define MRIM_COMPRESS_ZLIB   0

#define MRIM_CS_CAPABILITIES            0x1090  // C -> S
// DWORD capabilities_quantity
// DWORD cap_id_0
// LPS cap_value_0
// ...
// DWORD cap_id_quantity-1
// LPS cap_id_quantity-1
     #define MRIM_CAPABILITY_ONLINE_ALERTS   0
     #define MRIM_CAPABILITY_OFFLINE_ALERTS  1
     #define MRIM_CAPABILITY_WEBRTC          2
     #define MRIM_CAPABILITY_WEBRTC_BUSY     3
     #define MRIM_CAPABILITY_ARCH            4
     #define MRIM_CAPABILITY_NORTF           5
     #define MRIM_CAPABILITY_DEVICE_ID       6
     #define MRIM_CAPABILITY_PUBSUB          7
     #define MRIM_CAPABILITY_ARCH_STATES     41

#define MRIM_CS_ALERTS                  0x1091  // S -> C
// CLPS alerts


#define MRIM_CS_INVISIBLE_OUT           0x1093
// UL timeout

#define MRIM_CS_MY_ACTION        0x1094
//LPS utf8_xml
/*
xml example:

<?xml version="1.0" encoding="UTF-8"?>
<iq id="some_random_sequence_id">
  <like id="64_bit_hex_uppercase_id_from_my.mail.ru" action="like|unlike" />
</iq>
<iq id="some_random_sequence_id">
  <share id="should_be_returned_from_my.mail.ru"
url="http://some_url_shared_from_agent" />
</iq>

*/

#define MRIM_CS_MY_ACTION_ACK        0x1095
//LPS utf8_xml
/*
ack xml example:

<?xml version="1.0" encoding="UTF-8"?>
<iq id="some_random_sequence_id">
  <result status="OK|ERROR">
   <like id="64_bit_hex_uppercase_id_from_my.mail.ru" />
  </result>
</iq>
<iq id="some_random_sequence_id">
  <result status="OK|ERROR">
   <share id="returned_from_my.mail.ru" />
  </result>
</iq>

*/

// Deprecated. Use CS_OK, CS_FAILURE
#define MRIM_CS_RESULT                  0x1096  // C -> S, S -> C
// UL code
     #define MRIM_OK                     0
         #define MRIM_OK_STR                 "OK"
// LPS reason

#define MRIM_CS_ALLOCATE_VOIP_SESSION   0x1097  // C -> S
// [    optional
// UL   type (MRIM_PROXY_TYPE_WEBRTC_PHONE)
// LPS  phone_number (format: +<number>, ASCII)
// ]

#define MRIM_CS_VOIP_SESSION            0x1098  // S -> C
// LPS  session_id
// LPS  password
// LPS  stun_addresses (format: ip:port[;...])
// LPS  relay_udp_addresses
// LPS  relay_tcp_addresses
// LPS  rtmp_addresses

#define MRIM_CS_SET_BACKGROUND_PN_TOKEN 0x1099  // C -> S
// LPS  application
// LPS  tt_id (format: <transport>:<token id>)
// LPS  settings
// UL   timeout

//------------------------------------------------------------------------------------------------------------

#ifdef __cplusplus
namespace arch {
#endif

#define MRIM_CS_ARCH_RETRIVE_CHAT       0x1100 // C -> S
// LPS  with
// U64  after_id
// SL   to_slip
// TLV  options[] see enum Options

#ifdef __cplusplus
namespace retrieve {
namespace tags {

enum Options {
     exclude_list = 1, // do not send messages in list
           // U64 archive Id[]
};

} // tags
} // retrieve
#endif

#define MRIM_CS_ARCH_CHAT               0x1101 // S -> C
// LPS  with
// LPS  messages[]
//   LPS  message
//     U64  archive_id
//     UL   direction (message::Direction)
//     UL   time
//     TLV  body (enum Body)
//     TLV  attributes[] (enum Attributes)
// LPS  request_management
//   U64  last_id
//   UL   stop_slip


#ifdef __cplusplus
namespace message {

enum Direction
{
     to = 0,
     from = 1,
};

namespace tags {

enum Body
{
     plain = 0,
         // VAL  plain (UTF-8)
     multipart = 1,
         // TLV  formats[]
     header = 2,
};

namespace body {

enum Multipart
{
     plain = 0,
         // VAL  plain (UTF-8)
     alt = 1,
         // VAL
             // UL   count
             // LPS  rtf
             // LPS  background color
             // LPS  mult-tag (CP-1251)
             // LPS  mult-tag (UTF-16LE)
};

} // namespace body

enum Attribute
{
     sender = 0,
         // VAL  sender
     arch_state  = 1,
         // U32 code (enum State)
};

enum State
{
     sent      = 3,
     delivered = 4,
     read      = 5,
};

} // namespace tags

} // namespace message
#endif


#ifdef __cplusplus
} // namespace arch
#endif

//------------------------------------------------------------------------------------------------------------

#define MRIM_CS_SET_REALM 0x1102

#define MRIM_CS_TRANSCODER
//LPS from/to
//UL protocol
  #define MRIM_TRANSCODER_PROTOCOL_OSCAR 1
  #define MRIM_TRANSCODER_PROTOCOL_WIM 2
//LPS data
/*
transcoder data contains raw OSCAR or WIM packets

this data should be send to OSCAR in channel 7 and to WIM in some special
message

GUIDs and feature flags:
FEATURE_FLAG_WEBRTC | FEATURE_FLAG_AUDIO -
09461350-4C7F-11D1-8222-444553540000
FEATURE_FLAG_WEBRTC | FEATURE_FLAG_VIDEO -
09461351-4C7F-11D1-8222-444553540000
FEATURE_FLAG_GOOBER | FEATURE_FLAG_AUDIO -
09460104-4C7F-11D1-8222-444553540000
FEATURE_FLAG_GOOBER | FEATURE_FLAG_VIDEO -
09460101-4C7F-11D1-8222-444553540000
FEATURE_FLAG_FILE_TRANSFER - 09461343-4C7F-11D1-8222-444553540000
FEATURE_FLAG_INTEROP_TRANSCODING_SUPPORTED -
09461352-4C7F-11D1-8222-444553540000 - ïîääåðæêà êàíàëà 7

Full docs here:
https://confluence.mail.ru/pages/viewpage.action?pageId=15045154
*/

//------------------------------------------------------------------------------------------------------------

#define MRIM_CS_ARCH_ID 0x1103 // S -> C
// U32 Message id
// U64 Archive Id

#define MRIM_CS_ARCH_SYNC 0x1104 // S -> C
// LPS with
// LPS dialog version
// U32 unread msg count

#define MRIM_CS_ARCH_EVENT 0x1105 // C -> S
// LPS with
// U64 Archive Id
// U32 New State
//     STATE_SENT 3
//     STATE_DELIEVERED 4
//     STATE_READ 5

#define MRIM_CS_ARCH_PULL 0x1106 // C -> S
// LPS with
// LPS dialog version
// TLV Options[] (enum Options)
#ifdef __cplusplus
namespace arch {
namespace pull {

namespace tags {
enum Option {
     msg_limit = 1,
           // U32 limit for pulled messages
     readmsg_limit = 2,
           // U32 limit for read messages in pull
     chunk_size = 3,
           // U32 limit for size of pulled messages
     no_unreads =4,
           // U32 if client has no unread messages - set this flag
     body_exclude_list = 5, // do not send bodies for message in list
           // U64 archive Id[]
     state_restrict_range = 6, // do not send states for messages outside of range
           // U64 from   - earliest archive Id in local
           // U64 to     - latest archive Id in local
           // from:to (0,0) - in case of empty local history
};
} // tags

} // pull
} // arch
#endif

#define MRIM_CS_ARCH_HISTORY 0x1107 // S -> C
// LPS with
// LPS dialog version
// U32 flags
//     // DVER_FLAG_UNKNOWN 0x01
//     // DVER_FLAG_LAST    0x02 - all messages pulled
// LPS Messages[]
//     see CS_ARCH_CHAT

#define MRIM_CS_ARCH_STATE 0x1108 // C -> S
// LPS with

//------------------------------------------------------------------------------------------------------------

#define MRIM_CS_SELECT_ANKETAS      0x1109
// LPS  accounts[]
//   LPS  account_identifier
// LPS  fields[]
//   TLV  field

#ifdef __cplusplus
namespace anketa {
namespace tags {

enum Field
{
//    username = 1, always selected
     flags = 2,
     nickname = 3,
     firstName = 4,
     lastName = 5,
     sex = 6,
     birthday = 7,
     zodiac = 8,
     country_id = 9,
     city_id = 10,
     location = 11,
     phone = 12,
};

} // tags
} // anketa
#endif

#define MRIM_CS_ANKETAS             0x1110
// LPS  accounts[]
//   LPS  account
//     LPS  identifier
//     TLV  fields[]

//------------------------------------------------------------------------------------------------------------

#define MRIM_CS_PUBSUB_SUBSCRIBE    0x1111 // C -> S
// TLV  node

#ifdef __cplusplus
namespace pubsub {
namespace tags {

enum Node
{
     buddies_bdays = 0,
};

enum Entry
{
     buddy_bday = 0,
         // LPS  user
         // LPS  date (<year>-<month>-<day>)
         // LPS  notify message
};

} // tags
} // pubsub
#endif

#define MRIM_CS_PUBSUB_EVENT        0x1112 // S -> C
// TLV  node
// LPS  items[]
//   LPS    item
//     LPS  id
//     TLV  entry

#ifdef __cplusplus
} // namespace protocol
} // namespace mrim
#endif

#endif // MRIM_PROTO_H
