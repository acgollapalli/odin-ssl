/*
Package ssl implements bindings for version 4.0.0 of the portable release of LibreSSL (https://www.libressl.org)

This file implements bindings for 
*/

package libressl

import "core:c"
import "core:fmt"

when ODIN_OS == .Darwin {
    foreign import lib {
	"lib/darwin/tls.a"
    }
}


// we probably don't need these
// they use values that aren't defined in the header file

//  SSL_SESSION_ASN1_VERSION :: 0x0001
//  
//  /* text strings for the ciphers */
//  SSL_TXT_NULL_WITH_MD5 :: SSL2_TXT_NULL_WITH_MD5
//  SSL_TXT_RC4_128_WITH_MD5 :: SSL2_TXT_RC4_128_WITH_MD5
//  SSL_TXT_RC4_128_EXPORT40_WITH_MD5 :: SSL2_TXT_RC4_128_EXPORT40_WITH_MD5
//  SSL_TXT_RC2_128_CBC_WITH_MD5 :: SSL2_TXT_RC2_128_CBC_WITH_MD5
//  SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 :: SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5
//  SSL_TXT_IDEA_128_CBC_WITH_MD5 :: SSL2_TXT_IDEA_128_CBC_WITH_MD5
//  SSL_TXT_DES_64_CBC_WITH_MD5 :: SSL2_TXT_DES_64_CBC_WITH_MD5
//  SSL_TXT_DES_64_CBC_WITH_SHA :: SSL2_TXT_DES_64_CBC_WITH_SHA
//  SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 :: SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5
//  SSL_TXT_DES_192_EDE3_CBC_WITH_SHA :: SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA
//  
//  /*    VRS Additional Kerberos5 entries
//   */
//  SSL_TXT_KRB5_DES_64_CBC_SHA :: SSL3_TXT_KRB5_DES_64_CBC_SHA
//  SSL_TXT_KRB5_DES_192_CBC3_SHA :: SSL3_TXT_KRB5_DES_192_CBC3_SHA
//  SSL_TXT_KRB5_RC4_128_SHA :: SSL3_TXT_KRB5_RC4_128_SHA
//  SSL_TXT_KRB5_IDEA_128_CBC_SHA :: SSL3_TXT_KRB5_IDEA_128_CBC_SHA
//  SSL_TXT_KRB5_DES_64_CBC_MD5 :: SSL3_TXT_KRB5_DES_64_CBC_MD5
//  SSL_TXT_KRB5_DES_192_CBC3_MD5 :: SSL3_TXT_KRB5_DES_192_CBC3_MD5
//  SSL_TXT_KRB5_RC4_128_MD5 :: SSL3_TXT_KRB5_RC4_128_MD5
//  SSL_TXT_KRB5_IDEA_128_CBC_MD5 :: SSL3_TXT_KRB5_IDEA_128_CBC_MD5
//  
//  SSL_TXT_KRB5_DES_40_CBC_SHA :: SSL3_TXT_KRB5_DES_40_CBC_SHA
//  SSL_TXT_KRB5_RC2_40_CBC_SHA :: SSL3_TXT_KRB5_RC2_40_CBC_SHA
//  SSL_TXT_KRB5_RC4_40_SHA :: SSL3_TXT_KRB5_RC4_40_SHA
//  SSL_TXT_KRB5_DES_40_CBC_MD5 :: SSL3_TXT_KRB5_DES_40_CBC_MD5
//  SSL_TXT_KRB5_RC2_40_CBC_MD5 :: SSL3_TXT_KRB5_RC2_40_CBC_MD5
//  SSL_TXT_KRB5_RC4_40_MD5 :: SSL3_TXT_KRB5_RC4_40_MD5
//  
//  SSL_TXT_KRB5_DES_40_CBC_SHA :: SSL3_TXT_KRB5_DES_40_CBC_SHA
//  SSL_TXT_KRB5_DES_40_CBC_MD5 :: SSL3_TXT_KRB5_DES_40_CBC_MD5
//  SSL_TXT_KRB5_DES_64_CBC_SHA :: SSL3_TXT_KRB5_DES_64_CBC_SHA
//  SSL_TXT_KRB5_DES_64_CBC_MD5 :: SSL3_TXT_KRB5_DES_64_CBC_MD5
//  SSL_TXT_KRB5_DES_192_CBC3_SHA :: SSL3_TXT_KRB5_DES_192_CBC3_SHA
//  SSL_TXT_KRB5_DES_192_CBC3_MD5 :: SSL3_TXT_KRB5_DES_192_CBC3_MD5
//  SSL_MAX_KRB5_PRINCIPAL_LENGTH :: 256
//  
//  SSL_MAX_SSL_SESSION_ID_LENGTH :: 32
//  SSL_MAX_SID_CTX_LENGTH :: 32
//  
//  SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES :: (512/8)
//  SSL_MAX_KEY_ARG_LENGTH :: 8
//  SSL_MAX_MASTER_KEY_LENGTH :: 48


/* These are used to specify which ciphers to use and not to use */
SSL_TXT_LOW :: "LOW"
SSL_TXT_MEDIUM :: "MEDIUM"
SSL_TXT_HIGH :: "HIGH"

SSL_TXT_kFZA :: "kFZA" /* unused! */
SSL_TXT_aFZA :: "aFZA" /* unused! */
SSL_TXT_eFZA :: "eFZA" /* unused! */
SSL_TXT_FZA :: "FZA"  /* unused! */

SSL_TXT_aNULL :: "aNULL"
SSL_TXT_eNULL :: "eNULL"
SSL_TXT_NULL :: "NULL"

SSL_TXT_kRSA :: "kRSA"
SSL_TXT_kDHr :: "kDHr" /* no such ciphersuites supported! */
SSL_TXT_kDHd :: "kDHd" /* no such ciphersuites supported! */
SSL_TXT_kDH :: "kDH"  /* no such ciphersuites supported! */
SSL_TXT_kEDH :: "kEDH"
SSL_TXT_kKRB5 :: "kKRB5"
SSL_TXT_kECDHr :: "kECDHr"
SSL_TXT_kECDHe :: "kECDHe"
SSL_TXT_kECDH :: "kECDH"
SSL_TXT_kEECDH :: "kEECDH"
SSL_TXT_kPSK :: "kPSK"
SSL_TXT_kSRP :: "kSRP"

SSL_TXT_aRSA :: "aRSA"
SSL_TXT_aDSS :: "aDSS"
SSL_TXT_aDH :: "aDH" /* no such ciphersuites supported! */
SSL_TXT_aECDH :: "aECDH"
SSL_TXT_aKRB5 :: "aKRB5"
SSL_TXT_aECDSA :: "aECDSA"
SSL_TXT_aPSK :: "aPSK"

SSL_TXT_DSS :: "DSS"
SSL_TXT_DH :: "DH"
SSL_TXT_DHE :: "DHE" /* same as "kDHE:-ADH" */
SSL_TXT_EDH :: "EDH" /* previous name for DHE */
SSL_TXT_ADH :: "ADH"
SSL_TXT_RSA :: "RSA"
SSL_TXT_ECDH :: "ECDH"
SSL_TXT_ECDHE :: "ECDHE" /* same as "kECDHE:-AECDH" */
SSL_TXT_EECDH :: "EECDH" /* previous name for ECDHE */
SSL_TXT_AECDH :: "AECDH"
SSL_TXT_ECDSA :: "ECDSA"
SSL_TXT_KRB5 :: "KRB5"
SSL_TXT_PSK :: "PSK"
SSL_TXT_SRP :: "SRP"

SSL_TXT_DES :: "DES"
SSL_TXT_3DES :: "3DES"
SSL_TXT_RC4 :: "RC4"
SSL_TXT_RC2 :: "RC2"
SSL_TXT_IDEA :: "IDEA"
SSL_TXT_SEED :: "SEED"
SSL_TXT_AES128 :: "AES128"
SSL_TXT_AES256 :: "AES256"
SSL_TXT_AES :: "AES"
SSL_TXT_AES_GCM :: "AESGCM"
SSL_TXT_CAMELLIA128 :: "CAMELLIA128"
SSL_TXT_CAMELLIA256 :: "CAMELLIA256"
SSL_TXT_CAMELLIA :: "CAMELLIA"
SSL_TXT_CHACHA20 :: "CHACHA20"

SSL_TXT_AEAD :: "AEAD"
SSL_TXT_MD5 :: "MD5"
SSL_TXT_SHA1 :: "SHA1"
SSL_TXT_SHA :: "SHA" /* same as "SHA1" */
SSL_TXT_SHA256 :: "SHA256"
SSL_TXT_SHA384 :: "SHA384"

SSL_TXT_DTLS1 :: "DTLSv1"
SSL_TXT_DTLS1_2 :: "DTLSv1.2"
SSL_TXT_SSLV2 :: "SSLv2"
SSL_TXT_SSLV3 :: "SSLv3"
SSL_TXT_TLSV1 :: "TLSv1"
SSL_TXT_TLSV1_1 :: "TLSv1.1"
SSL_TXT_TLSV1_2 :: "TLSv1.2"
SSL_TXT_TLSV1_3 :: "TLSv1.3"

SSL_TXT_EXP :: "EXP"
SSL_TXT_EXPORT :: "EXPORT"

SSL_TXT_ALL :: "ALL"

/*
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
SSL_TXT_CMPALL :: "COMPLEMENTOFALL"
SSL_TXT_CMPDEF :: "COMPLEMENTOFDEFAULT"

/* The following cipher list is used by default.
 * It also is substituted when an application-defined cipher list string
 * starts with 'DEFAULT'. */
SSL_DEFAULT_CIPHER_LIST :: "ALL:!aNULL:!eNULL:!SSLv2"
/* As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
 * starts with a reasonable order, and all we have to do for DEFAULT is
 * throwing out anonymous and unencrypted ciphersuites!
 * (The latter are not actually enabled by ALL, but "ALL:RSA" would enable
 * some of them.)
 */

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
SSL_SENT_SHUTDOWN :: 1
SSL_RECEIVED_SHUTDOWN :: 2


/* opaque and may not be needed by us */
//SSL_FILETYPE_ASN1 :: X509_FILETYPE_ASN1
//SSL_FILETYPE_PEM :: X509_FILETYPE_PEM

SSL:: distinct rawptr
SSL_CTX :: distinct rawptr
SSL_METHOD :: distinct rawptr
SSL_CIPHER :: distinct rawptr
STACK_OF_SSL_CIPHER :: distinct rawptr // FIXME: figure out whether we can (or need to) use a multipointer for this

tls_session_ticket_ext_cb_fn :: #type proc "c"(
    s: SSL,
    data: [^]c.uchar,
    len: c.int,
    arg: rawptr
) -> c.int

tls_session_secret_cb_fn :: #type proc "c"(
    s: SSL,
    secret: rawptr,
    secret_len: ^c.int,
    peer_ciphers: STACK_OF_SSL_CIPHER,
    cipher: ^SSL_CIPHER,
    arg: rawptr
) -> c.int

/* Allow initial connection to servers that don't support RI */
SSL_OP_LEGACY_SERVER_CONNECT :: 0x00000004 // LONG

/* Disable SSL 3.0/TLS 1.0 CBC vulnerability workaround that was added
 * in OpenSSL 0.9.6d.  Usually (depending on the application protocol)
 * the workaround is not needed.
 * Unfortunately some broken SSL/TLS implementations cannot handle it
 * at all, which is why it was previously included in SSL_OP_ALL.
 * Now it's not.
 */
SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS :: 0x00000800 // LONG

/* DTLS options */
SSL_OP_NO_QUERY_MTU :: 0x00001000 // LONG
/* Turn on Cookie Exchange (on relevant for servers) */
SSL_OP_COOKIE_EXCHANGE :: 0x00002000 // LONG
/* Don't use RFC4507 ticket extension */
SSL_OP_NO_TICKET :: 0x00004000 // LONG

/* As server, disallow session resumption on renegotiation */
SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION :: 0x00010000 // LONG
/* Disallow client initiated renegotiation. */
SSL_OP_NO_CLIENT_RENEGOTIATION :: 0x00020000 // LONG
/* If set, always create a new key when using tmp_dh parameters */
SSL_OP_SINGLE_DH_USE :: 0x00100000 // LONG
/* Set on servers to choose the cipher according to the server's
 * preferences */
SSL_OP_CIPHER_SERVER_PREFERENCE :: 0x00400000 // LONG

SSL_OP_NO_TLSv1 :: 0x04000000 // LONG
SSL_OP_NO_TLSv1_2 :: 0x08000000 // LONG
SSL_OP_NO_TLSv1_1 :: 0x10000000 //LONG

SSL_OP_NO_TLSv1_3 :: 0x20000000 // LONG

SSL_OP_NO_DTLSv1 :: 0x40000000 // LONG
SSL_OP_NO_DTLSv1_2 :: 0x80000000 // LONG

/* SSL_OP_ALL: various bug workarounds that should be rather harmless. */
SSL_OP_ALL :: SSL_OP_LEGACY_SERVER_CONNECT

/* Obsolete flags kept for compatibility. No sane code should use them. */
SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION :: 0x0
SSL_OP_CISCO_ANYCONNECT :: 0x0
SSL_OP_CRYPTOPRO_TLSEXT_BUG :: 0x0
SSL_OP_EPHEMERAL_RSA :: 0x0
SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER :: 0x0
SSL_OP_MICROSOFT_SESS_ID_BUG :: 0x0
SSL_OP_MSIE_SSLV2_RSA_PADDING :: 0x0
SSL_OP_NETSCAPE_CA_DN_BUG :: 0x0
SSL_OP_NETSCAPE_CHALLENGE_BUG :: 0x0
SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG :: 0x0
SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG :: 0x0
SSL_OP_NO_COMPRESSION :: 0x0
SSL_OP_NO_SSLv2 :: 0x0
SSL_OP_NO_SSLv3 :: 0x0
SSL_OP_PKCS1_CHECK_1 :: 0x0
SSL_OP_PKCS1_CHECK_2 :: 0x0
SSL_OP_SAFARI_ECDHE_ECDSA_BUG :: 0x0
SSL_OP_SINGLE_ECDH_USE :: 0x0
SSL_OP_SSLEAY_080_CLIENT_DH_BUG :: 0x0
SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG :: 0x0
SSL_OP_TLSEXT_PADDING :: 0x0
SSL_OP_TLS_BLOCK_PADDING_BUG :: 0x0
SSL_OP_TLS_D5_BUG :: 0x0
SSL_OP_TLS_ROLLBACK_BUG :: 0x0

/* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written): */
SSL_MODE_ENABLE_PARTIAL_WRITE :: 0x00000001 // long
/* Make it possible to retry SSL_write() with changed buffer location
 * (buffer contents must stay the same!); this is not the default to avoid
 * the misconception that non-blocking SSL_write() behaves like
 * non-blocking write(): */
SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER :: 0x00000002 //long
/* Never bother the application with retries if the transport
 * is blocking: */
SSL_MODE_AUTO_RETRY :: 0x00000004 // long
/* Don't attempt to automatically build certificate chain */
SSL_MODE_NO_AUTO_CHAIN :: 0x00000008 //long
/* Save RAM by releasing read and write buffers when they're empty. (SSL3 and
 * TLS only.)  "Released" buffers are put onto a free-list in the context
 * or just freed (depending on the context's setting for freelist_max_len). */
SSL_MODE_RELEASE_BUFFERS :: 0x00000010 // long

X509 :: distinct rawptr
STACK_OF_X509 :: distinct rawptr

SSL_Msg_Callback :: #type proc "c"(
    write_p: c.int,
    version: c.int,
    content_type:
    c.int, buf: rawptr,
    len: c.size_t,
    ssl: SSL,
    arg: rawptr
)
SSL_CTX_keylog_cb_func :: #type proc "c"(ssl: SSL, line: cstring)

@(default_calling_convention="c")
foreign lib  {
/* Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
 * they cannot be used to clear bits. */
    SSL_CTX_set_options :: proc(ctx: SSL_CTX, op: c.long) -> c.long ---
    SSL_CTX_clear_options :: proc(ctx: SSL_CTX, op: c.long) -> c.long ---

    SSL_CTX_get_options :: proc(ctx: SSL_CTX) -> c.long --- 
    SSL_set_options :: proc(ssl: SSL,op: c.long) -> c.long --- 
    SSL_clear_options :: proc(ssl: SSL,op: c.long) -> c.long --- 
    SSL_get_options :: proc(ssl: SSL) -> c.long --- 
    
    SSL_CTX_set_mode :: proc(ctx: SSL_CTX,op: c.long) -> c.long --- 
    SSL_CTX_clear_mode :: proc(ctx: SSL_CTX,op: c.long) -> c.long ---
    SSL_CTX_get_mode :: proc(ctx: SSL_CTX) -> c.long --- 
    SSL_clear_mode :: proc(ssl: SSL,op: c.long) -> c.long ---
    SSL_set_mode :: proc(ssl: SSL,op: c.long) -> c.long --- 
    SSL_get_mode :: proc(ssl: SSL) -> c.long --- 
    SSL_set_mtu :: proc(ssl: SSL, mtu: c.long) -> c.long --- 
    
    SSL_get_secure_renegotiation_support :: proc(ssl: SSL) -> c.long ---


    
    SSL_CTX_set_msg_callback :: proc(ctx: SSL_CTX, cb: SSL_Msg_Callback) ---
    SSL_set_msg_callback :: proc(ssl: SSL, cb: SSL_Msg_Callback) ---


    SSL_CTX_set_msg_callback_arg :: proc(ctx: SSL_CTX, arg: rawptr) -> c.long ---
    SSL_set_msg_callback_arg :: proc(ssl: SSL, arg: rawptr) -> c.long ---

    SSL_CTX_set_keylog_callback :: proc(ctx: SSL_CTX, cb: SSL_CTX_keylog_cb_func) ---
    SSL_CTX_get_keylog_callback :: proc(ctx: SSL_CTX) -> SSL_CTX_keylog_cb_func ---

    SSL_set_num_tickets :: proc(s: SSL, num_tickets: c.size_t) -> c.int ---
    SSL_get_num_tickets :: proc(s: SSL) -> c.size_t ---
    SSL_CTX_set_num_tickets :: proc(ctx: SSL_CTX, num_tickets: c.size_t) -> c.int ---
    SSL_CTX_get_num_tickets :: proc(ctx: SSL_CTX) -> c.size_t ---

    SSL_get0_verified_chain :: proc(s: SSL) -> STACK_OF_X509 ---
}

SSL_MAX_CERT_LIST_DEFAULT :: 1024*100 /* 100k max cert list :-) */

SSL_SESSION_CACHE_MAX_SIZE_DEFAULT :: 1024*20

/* This callback type is used inside SSL_CTX, SSL, and in the functions that set
 * them. It is used to override the generation of SSL/TLS session IDs in a
 * server. Return value should be zero on an error, non-zero to proceed. Also,
 * callbacks should themselves check if the id they generate is unique otherwise
 * the SSL handshake will fail with an error - callbacks can do this using the
 * 'ssl' value they're passed by;
 *      SSL_has_matching_session_id(ssl, id, *id_len)
 * The length value passed in is set at the maximum size the session ID can be.
 * In SSLv2 this is 16 bytes, whereas SSLv3/TLSv1 it is 32 bytes. The callback
 * can alter this length to be less if desired, but under SSLv2 session IDs are
 * supposed to be fixed at 16 bytes so the id will be padded after the callback
 * returns in this case. It is also an error for the callback to set the size to
 * zero. */
GEN_SESSION_CB :: #type proc "c" (ssl: SSL, id: cstring, id_len: ^c.uint) -> c.int

SSL_COMP :: distinct rawptr

STACK_OF_SSL_COMP :: distinct rawptr
lhash_st_SSL_SESSION :: struct {
dummy: c.int
}

SSL_SESS_CACHE_OFF :: 0x0000
SSL_SESS_CACHE_CLIENT :: 0x0001
SSL_SESS_CACHE_SERVER :: 0x0002
SSL_SESS_CACHE_BOTH :: SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER
SSL_SESS_CACHE_NO_AUTO_CLEAR :: 0x0080
/* enough comments already ... see SSL_CTX_set_session_cache_mode(3) */
SSL_SESS_CACHE_NO_INTERNAL_LOOKUP :: 0x0100
SSL_SESS_CACHE_NO_INTERNAL_STORE :: 0x0200
SSL_SESS_CACHE_NO_INTERNAL :: SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE

LHASH_SSL_SESSION :: distinct rawptr

SSL_ST :: rawptr
SSL_CTX_ST :: rawptr
SSL_SESSION :: distinct rawptr
EVP_PKEY :: distinct rawptr
EVP_MD :: distinct rawptr


SSL_Sess_New_Callback :: #type proc "c"(ssl: SSL_ST, sess: SSL_SESSION) -> int
SSL_Sess_Remove_Callback :: #type proc "c"(ctx: SSL_CTX_ST, sess: SSL_SESSION) -> int
SSL_Sess_Get_Callback :: #type proc "c"(ssl: SSL_ST, data: [^]c.uchar, len: c.int, copy: ^c.int) -> SSL_SESSION
SSL_Info_Callback :: #type proc "c"(ssl: SSL,type: c.int, val: c.int)
SSL_Client_Cert_Callback :: #type proc "c"(ssl: SSL, x590: ^X509, pkey: ^EVP_PKEY)
SSL_Cookie_Generate_Callback :: #type proc "c"(ssl: SSL, cookie: cstring, cookie_len: ^c.uint)
SSL_Cookie_Verify_Callback :: #type proc "c"(ssl: SSL, cookie: cstring, cookie_len: c.uint) -> c.int
SSL_Next_Protos_Advertised_Callback :: #type proc "c"(ssl: SSL, out: ^[^]c.uchar, outlen: ^c.uint) -> int
SSL_Next_Proto_Select_CB :: #type proc "c"(ssl: SSL, out: ^[^]c.uchar, outlen: [^]c.uchar, input: ^c.uchar, inlen: c.uint, arg: rawptr)

@(default_calling_convention="c")
foreign lib {
    SSL_CTX_sessions :: proc(ctx: SSL_CTX) -> LHASH_SSL_SESSION ---
    
    SSL_CTX_sess_number :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_connect :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_connect_good :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_connect_renegotiate :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_accept :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_accept_renegotiate :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_accept_good :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_hits :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_cb_hits :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_misses :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_timeouts :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_sess_cache_full :: proc(ctx: SSL_CTX) -> c.long ---

    SSL_CTX_sess_set_new_cb :: proc(ctx: SSL_CTX, new_session_cb: SSL_Sess_New_Callback) ---
    SSL_CTX_sess_get_new_cb ::proc(ctx: SSL_CTX) -> SSL_Sess_New_Callback ---

    SSL_CTX_sess_set_remove_cb :: proc(ctx: SSL_CTX, remove_session_cb: SSL_Sess_Remove_Callback) ---
    SSL_CTX_sess_get_remove_cb :: proc(ctx: SSL_CTX) -> SSL_Sess_Remove_Callback ---

    SSL_CTX_sess_set_get_cb :: proc(ctx: SSL_CTX, get_session_cb: SSL_Sess_Get_Callback) ---
    SSL_CTX_sess_get_get_cb :: proc(ctx: SSL_CTX) -> SSL_Sess_Get_Callback ---

    SSL_CTX_set_info_callback :: proc(ctx: SSL_CTX, cb: SSL_Info_Callback) ---
    SSL_CTX_get_info_callback :: proc(ctx: SSL_CTX) -> SSL_Info_Callback ---

    SSL_CTX_set_client_cert_cb :: proc(ctx: SSL_CTX, client_cert_cb: SSL_Client_Cert_Callback) ---
    SSL_CTX_get_client_cert_cb :: proc(ctx: SSL_CTX) -> SSL_Client_Cert_Callback ---

    SSL_CTX_set_cookie_generate_cb :: proc(ctx: SSL_CTX, app_gen_cookie_cb: SSL_Cookie_Generate_Callback) ---

    SSL_CTX_set_cookie_verify_cb :: proc(ctx: SSL_CTX , app_verify_cookie_cb: SSL_Cookie_Verify_Callback) ---

    SSL_CTX_set_next_protos_advertised_cb :: proc(s: SSL_CTX, cb: SSL_Next_Protos_Advertised_Callback, arg: rawptr) ---
    SSL_CTX_set_next_proto_select_cb :: proc(s: SSL_CTX, cb: SSL_Next_Proto_Select_CB, arg: rawptr) ---

    SSL_select_next_proto :: proc(out: ^[^]c.uchar, outlen: ^c.uchar, input: ^[^]c.uchar, inlen: c.uint, client: [^]c.uchar, client_len: c.uint) -> int ---
    SSL_get0_next_proto_negotiated :: proc(s: SSL, data: ^[^]c.uchar, len: ^c.uint) ---
}
OPENSSL_NPN_UNSUPPORTED :: 0
OPENSSL_NPN_NEGOTIATED :: 1
OPENSSL_NPN_NO_OVERLAP :: 2

SSL_psk_use_session_cb_func :: #type proc "c"(ssl: SSL, md: EVP_MD, id: ^[^]c.uchar, idlen: ^c.size_t, sess: ^SSL_SESSION) -> int
SSL_Alpn_Select_Callback :: #type proc "c"(ssl: SSL, out: ^[^]c.uchar, outlen: ^c.uchar, input: ^c.uchar, inlen: c.uint, void: rawptr) -> int

@(default_calling_convention="c")
foreign lib {
    SSL_CTX_set_alpn_protos :: proc(ctx: SSL_CTX, protos: ^c.uchar, protos_len: c.uint) -> int ---
    SSL_set_alpn_protos :: proc(ssl: SSL, protos: ^c.uchar, protos_len: c.uint) -> int ---

    SSL_CTX_set_alpn_select_cb :: proc(ctx: SSL_CTX, cb: SSL_Alpn_Select_Callback, arg: rawptr) ---
    SSL_get0_alpn_selected :: proc(ssl: SSL, data: ^[^]c.uchar, len: ^c.uint) ---
    SSL_set_psk_use_session_callback :: proc(s: SSL, cb: SSL_psk_use_session_cb_func) ---
}


SSL_NOTHING :: 1
SSL_WRITING :: 2
SSL_READING :: 3
SSL_X509_LOOKUP	:: 4

SSL_MAC_FLAG_READ_MAC_STREAM :: 1
SSL_MAC_FLAG_WRITE_MAC_STREAM :: 2

@(default_calling_convention="c")
foreign lib {
    /* These will only be used when doing non-blocking IO */
    SSL_want_nothing :: proc(s: SSL) -> bool ---
    SSL_want_read :: proc(s: SSL) -> bool ---
    SSL_want_write :: proc(s: SSL) -> bool ---
    SSL_want_x509_lookup :: proc(s: SSL) -> bool ---


/* compatibility */
    SSL_get_app_data :: proc(s: SSL) ---
    SSL_set_app_data :: proc(s: SSL,arg: rawptr) -> c.int ---
    SSL_SESSION_get_app_data :: proc(s: SSL_CTX) ---
    SSL_SESSION_set_app_data :: proc(s: SSL_SESSION,a: rawptr) -> int ---
    SSL_CTX_get_app_data :: proc(ctx: SSL_CTX) ---
    SSL_CTX_set_app_data :: proc(ctx: SSL_CTX, arg: rawptr) -> int ---
}

/* The following are the possible values for ssl->state are are
 * used to indicate where we are up to in the SSL connection establishment.
 * The macros that follow are about the only things you should need to use
 * and even then, only when using non-blocking IO.
 * It can also be useful to work out where you were when the connection
 * failed */

SSL_ST_CONNECT :: 0x1000
SSL_ST_ACCEPT :: 0x2000
SSL_ST_MASK :: 0x0FFF
SSL_ST_INIT :: SSL_ST_CONNECT | SSL_ST_ACCEPT
SSL_ST_BEFORE :: 0x4000
SSL_ST_OK :: 0x03
SSL_ST_RENEGOTIATE :: 0x04 | SSL_ST_INIT

SSL_CB_LOOP :: 0x01
SSL_CB_EXIT :: 0x02
SSL_CB_READ :: 0x04
SSL_CB_WRITE :: 0x08
SSL_CB_ALERT :: 0x4000 /* used in callback */
SSL_CB_READ_ALERT :: SSL_CB_ALERT | SSL_CB_READ
SSL_CB_WRITE_ALERT :: SSL_CB_ALERT | SSL_CB_WRITE
SSL_CB_ACCEPT_LOOP :: SSL_ST_ACCEPT | SSL_CB_LOOP
SSL_CB_ACCEPT_EXIT :: SSL_ST_ACCEPT | SSL_CB_EXIT
SSL_CB_CONNECT_LOOP :: SSL_ST_CONNECT | SSL_CB_LOOP
SSL_CB_CONNECT_EXIT :: SSL_ST_CONNECT | SSL_CB_EXIT
SSL_CB_HANDSHAKE_START :: 0x10
SSL_CB_HANDSHAKE_DONE :: 0x20

@(default_calling_convention="c")
foreign lib  {
    /* Is the SSL_connection established? */
    SSL_get_state :: proc(a: SSL) -> c.int --- /* WHY IS THE ARGUMENT A?! */
    SSL_is_init_finished :: proc(a: SSL) -> c.int ---
    SSL_in_init :: proc(a: SSL) -> c.int ---
    SSL_in_before :: proc(a: SSL) -> c.int ---
    SSL_in_connect_init :: proc(a: SSL) -> c.int ---
    SSL_in_accept_init :: proc(a: SSL) -> c.int ---

}
/* The following 2 states are kept in ssl->rstate when reads fail,
 * you should not need these */
SSL_ST_READ_HEADER :: 0xF0
SSL_ST_READ_BODY :: 0xF1
SSL_ST_READ_DONE :: 0xF2

@(default_calling_convention="c")
foreign lib  {
    /* Obtain latest Finished message
     *   -- that we sent (SSL_get_finished)
     *   -- that we expected from peer (SSL_get_peer_finished).
     * Returns length (0 == no Finished so far), copies up to 'count' bytes. */
    SSL_get_finished :: proc(s: SSL, buf: rawptr, count: c.size_t) -> c.size_t ---
    SSL_get_peer_finished :: proc(s: SSL, buf: rawptr, count: c.size_t) -> c.size_t ---
}

/* use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired */
SSL_VERIFY_NONE :: 0x00
SSL_VERIFY_PEER :: 0x01
SSL_VERIFY_FAIL_IF_NO_PEER_CERT :: 0x02
SSL_VERIFY_CLIENT_ONCE :: 0x04
    SSL_VERIFY_POST_HANDSHAKE :: 0x08

@(default_calling_convention="c")
foreign lib  {
SSL_verify_client_post_handshake :: proc(s: SSL) -> c.int ---
SSL_CTX_set_post_handshake_auth :: proc(ctx: SSL_CTX, val: c.int) ---
SSL_set_post_handshake_auth :: proc(s: SSL, val: c.int) ---
}

BIO :: distinct rawptr
FILE :: distinct rawptr

pem_password_cb :: distinct rawptr

@(default_calling_convention="c")
foreign lib {
    OpenSSL_add_ssl_algorithms :: proc() -> c.int ---
    SSLeay_add_ssl_algorithms :: proc() -> c.int ---

    /* these are for c libraries that were reliant on older versions
       of libressl or openssl. I've included them for completeness
       you should not use them. */

    /* More backward compatibility */
    SSL_get_cipher :: proc(s: SSL) -> cstring ---
    SSL_get_cipher_bits :: proc(s: SSL, np: ^c.int) -> cstring ---
    SSL_get_cipher_version :: proc(s: SSL) -> cstring ---
    SSL_get_cipher_name :: proc(s: SSL) -> cstring ---
    SSL_get_time :: proc(a: SSL_SESSION) -> c.long ---
    SSL_set_time :: proc(a: SSL_SESSION,b: c.long) -> c.long ---
    SSL_get_timeout :: proc(a: SSL_SESSION) -> c.long ---
    SSL_set_timeout :: proc(a: SSL_SESSION,b: c.long) -> c.long ---

    // FIXME: these are crytpography functions and I'd be
    // willing to bet you sholdn't use them directly
    // WARNING: I am not sure I have these typed correctly
    // You should check the ssl.h and asn1.h to configm before using
    d2i_SSL_SESSION_bio :: proc(bp: BIO,s_id: ^SSL_SESSION) -> rawptr ---
    i2d_SSL_SESSION_bio :: proc(bp: BIO,s_id: ^SSL_SESSION) -> rawptr ---

    PEM_read_bio_SSL_SESSION :: proc(bp: BIO, x: ^SSL_SESSION,  cb: pem_password_cb, u: rawptr) -> SSL_SESSION ---
    PEM_read_SSL_SESSION :: proc(fp: FILE, x: ^SSL_SESSION, cb: pem_password_cb, u: rawptr) -> SSL_SESSION ---
    PEM_write_bio_SSL_SESSION :: proc(bp: BIO, x: SSL_SESSION) -> c.int ---
    PEM_write_SSL_SESSION :: proc(fp: FILE, x: SSL_SESSION) -> c.int ---
}

/*
 * TLS Alerts.
 *
 * https://www.iana.org/assignments/tls-parameters/#tls-parameters-6
 */

/* Obsolete alerts. */
SSL_AD_DECRYPTION_FAILED :: 21	/* Removed in TLSv1.1 */
SSL_AD_NO_CERTIFICATE :: 41	/* Removed in TLSv1.0 */
SSL_AD_EXPORT_RESTRICTION :: 60	/* Removed in TLSv1.1 */

SSL_AD_CLOSE_NOTIFY :: 0
SSL_AD_UNEXPECTED_MESSAGE :: 10
SSL_AD_BAD_RECORD_MAC :: 20
SSL_AD_RECORD_OVERFLOW :: 22
SSL_AD_DECOMPRESSION_FAILURE :: 30	/* Removed in TLSv1.3 */
SSL_AD_HANDSHAKE_FAILURE :: 40
SSL_AD_BAD_CERTIFICATE :: 42
SSL_AD_UNSUPPORTED_CERTIFICATE :: 43
SSL_AD_CERTIFICATE_REVOKED :: 44
SSL_AD_CERTIFICATE_EXPIRED :: 45
SSL_AD_CERTIFICATE_UNKNOWN :: 46
SSL_AD_ILLEGAL_PARAMETER :: 47
SSL_AD_UNKNOWN_CA :: 48
SSL_AD_ACCESS_DENIED :: 49
SSL_AD_DECODE_ERROR :: 50
SSL_AD_DECRYPT_ERROR :: 51
SSL_AD_PROTOCOL_VERSION :: 70
SSL_AD_INSUFFICIENT_SECURITY :: 71
SSL_AD_INTERNAL_ERROR :: 80
SSL_AD_INAPPROPRIATE_FALLBACK :: 86
SSL_AD_USER_CANCELLED :: 90
SSL_AD_NO_RENEGOTIATION :: 100	/* Removed in TLSv1.3 */
SSL_AD_MISSING_EXTENSION :: 109	/* Added in TLSv1.3. */
SSL_AD_UNSUPPORTED_EXTENSION :: 110
SSL_AD_CERTIFICATE_UNOBTAINABLE :: 111	/* Removed in TLSv1.3 */
SSL_AD_UNRECOGNIZED_NAME :: 112
SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE :: 113
SSL_AD_BAD_CERTIFICATE_HASH_VALUE :: 114	/* Removed in TLSv1.3 */
SSL_AD_UNKNOWN_PSK_IDENTITY :: 115
SSL_AD_CERTIFICATE_REQUIRED :: 116
SSL_AD_NO_APPLICATION_PROTOCOL :: 120

/* Offset to get an SSL_R_... value from an SSL_AD_... value. */
SSL_AD_REASON_OFFSET :: 1000

SSL_ERROR_NONE :: 0
SSL_ERROR_SSL :: 1
SSL_ERROR_WANT_READ :: 2
SSL_ERROR_WANT_WRITE :: 3
SSL_ERROR_WANT_X509_LOOKUP :: 4
SSL_ERROR_SYSCALL :: 5
SSL_ERROR_ZERO_RETURN :: 6
SSL_ERROR_WANT_CONNECT :: 7
SSL_ERROR_WANT_ACCEPT :: 8
SSL_ERROR_WANT_ASYNC :: 9
SSL_ERROR_WANT_ASYNC_JOB :: 10
SSL_ERROR_WANT_CLIENT_HELLO_CB :: 11

SSL_CTRL_NEED_TMP_RSA :: 1
SSL_CTRL_SET_TMP_RSA :: 2
SSL_CTRL_SET_TMP_DH :: 3
SSL_CTRL_SET_TMP_ECDH :: 4
SSL_CTRL_SET_TMP_RSA_CB :: 5
SSL_CTRL_SET_TMP_DH_CB :: 6
SSL_CTRL_SET_TMP_ECDH_CB :: 7

SSL_CTRL_GET_SESSION_REUSED :: 8
SSL_CTRL_GET_CLIENT_CERT_REQUEST :: 9
SSL_CTRL_GET_NUM_RENEGOTIATIONS :: 10
SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS :: 11
SSL_CTRL_GET_TOTAL_RENEGOTIATIONS :: 12
SSL_CTRL_GET_FLAGS :: 13
SSL_CTRL_EXTRA_CHAIN_CERT :: 14

SSL_CTRL_SET_MSG_CALLBACK :: 15
SSL_CTRL_SET_MSG_CALLBACK_ARG :: 16

/* only applies to datagram connections */
SSL_CTRL_SET_MTU :: 17
/* Stats */
SSL_CTRL_SESS_NUMBER :: 20
SSL_CTRL_SESS_CONNECT :: 21
SSL_CTRL_SESS_CONNECT_GOOD :: 22
SSL_CTRL_SESS_CONNECT_RENEGOTIATE :: 23
SSL_CTRL_SESS_ACCEPT :: 24
SSL_CTRL_SESS_ACCEPT_GOOD :: 25
SSL_CTRL_SESS_ACCEPT_RENEGOTIATE :: 26
SSL_CTRL_SESS_HIT :: 27
SSL_CTRL_SESS_CB_HIT :: 28
SSL_CTRL_SESS_MISSES :: 29
SSL_CTRL_SESS_TIMEOUTS :: 30
SSL_CTRL_SESS_CACHE_FULL :: 31
SSL_CTRL_OPTIONS :: 32
SSL_CTRL_MODE :: 33

SSL_CTRL_GET_READ_AHEAD :: 40
SSL_CTRL_SET_READ_AHEAD :: 41
SSL_CTRL_SET_SESS_CACHE_SIZE :: 42
SSL_CTRL_GET_SESS_CACHE_SIZE :: 43
SSL_CTRL_SET_SESS_CACHE_MODE :: 44
SSL_CTRL_GET_SESS_CACHE_MODE :: 45

SSL_CTRL_GET_MAX_CERT_LIST :: 50
SSL_CTRL_SET_MAX_CERT_LIST :: 51

SSL_CTRL_SET_MAX_SEND_FRAGMENT :: 52

/* see tls1.h for macros based on these */
SSL_CTRL_SET_TLSEXT_SERVERNAME_CB :: 53
SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG :: 54
SSL_CTRL_SET_TLSEXT_HOSTNAME :: 55
SSL_CTRL_SET_TLSEXT_DEBUG_CB :: 56
SSL_CTRL_SET_TLSEXT_DEBUG_ARG :: 57
SSL_CTRL_GET_TLSEXT_TICKET_KEYS :: 58
SSL_CTRL_SET_TLSEXT_TICKET_KEYS :: 59
SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB :: 128
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB :: 63
SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG :: 129
SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG :: 64
SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE :: 127
SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE :: 65
SSL_CTRL_GET_TLSEXT_STATUS_REQ_EXTS :: 66
SSL_CTRL_SET_TLSEXT_STATUS_REQ_EXTS :: 67
SSL_CTRL_GET_TLSEXT_STATUS_REQ_IDS :: 68
SSL_CTRL_SET_TLSEXT_STATUS_REQ_IDS :: 69
SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP :: 70
SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP :: 71

SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB :: 72

SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB :: 75
SSL_CTRL_SET_SRP_VERIFY_PARAM_CB :: 76
SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB :: 77

SSL_CTRL_SET_SRP_ARG :: 78
SSL_CTRL_SET_TLS_EXT_SRP_USERNAME :: 79
SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH :: 80
SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD :: 81

DTLS_CTRL_GET_TIMEOUT :: 73
DTLS_CTRL_HANDLE_TIMEOUT :: 74
DTLS_CTRL_LISTEN :: 75

SSL_CTRL_GET_RI_SUPPORT :: 76
SSL_CTRL_CLEAR_OPTIONS :: 77
SSL_CTRL_CLEAR_MODE :: 78

SSL_CTRL_GET_EXTRA_CHAIN_CERTS :: 82
SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS :: 83

SSL_CTRL_CHAIN :: 88
SSL_CTRL_CHAIN_CERT :: 89

SSL_CTRL_SET_GROUPS :: 91
SSL_CTRL_SET_GROUPS_LIST :: 92
SSL_CTRL_GET_SHARED_GROUP :: 93
SSL_CTRL_SET_ECDH_AUTO :: 94

SSL_CTRL_GET_PEER_SIGNATURE_NID :: 108
SSL_CTRL_GET_PEER_TMP_KEY :: 109
SSL_CTRL_GET_SERVER_TMP_KEY :: SSL_CTRL_GET_PEER_TMP_KEY

SSL_CTRL_GET_CHAIN_CERTS :: 115

SSL_CTRL_SET_DH_AUTO :: 118

SSL_CTRL_SET_MIN_PROTO_VERSION :: 123
SSL_CTRL_SET_MAX_PROTO_VERSION :: 124
SSL_CTRL_GET_MIN_PROTO_VERSION :: 130
SSL_CTRL_GET_MAX_PROTO_VERSION :: 131

SSL_CTRL_GET_SIGNATURE_NID :: 132


BIO_METHOD :: distinct rawptr
X509_STORE :: distinct rawptr


SSL_CTRL_SET_CURVES :: SSL_CTRL_SET_GROUPS
SSL_CTRL_SET_CURVES_LIST :: SSL_CTRL_SET_GROUPS_LIST

SSL_CTX_set1_curves :: SSL_CTX_set1_groups
SSL_CTX_set1_curves_list :: SSL_CTX_set1_groups_list
SSL_set1_curves :: SSL_set1_groups
SSL_set1_curves_list :: SSL_set1_groups_list
SSL_get_shared_curve :: SSL_get_shared_group

X509_STORE_CTX :: distinct rawptr
SSL_verify_callback :: #type proc(n: c.int, store: X509_STORE_CTX) -> c.int
RSA :: distinct rawptr
STACK_OF_X509_NAME :: distinct rawptr
SSL_cert_verify_callback :: #type proc(store: X509_STORE_CTX, arg: rawptr) -> c.int

X509_VERIFY_PARAM :: distinct rawptr
SSL_void_callback :: #type proc() -> rawptr

SSL_EARLY_DATA_NOT_SENT :: 0
SSL_EARLY_DATA_REJECTED :: 1
SSL_EARLY_DATA_ACCEPTED :: 2


SSL_READ_EARLY_DATA_ERROR :: 0
SSL_READ_EARLY_DATA_SUCCESS :: 1
SSL_READ_EARLY_DATA_FINISH :: 2


    SSL_get0_session :: SSL_get_session /* just peek at pointer */
SSL_info_callback :: #type proc(ssl: SSL, type: c.int, val: c.int)
    CRYPTO_EX_new :: distinct rawptr 
    CRYPTO_EX_dup :: distinct rawptr
    CRYPTO_EX_free :: distinct rawptr
SSL_tmp_RSA_callback :: #type proc(ssl: SSL, is_export: c.int, keylength: c.int) -> RSA


    DH :: distinct rawptr /* Diffie Hellman */
SSL_tmp_DH_callback :: #type proc(ssl: SSL, is_export: c.int, keylength: c.int) -> DH


    EC_KEY :: distinct rawptr /* Elliptic Curve Diffie Hellman */
    SSL_tmp_ECDH_callback :: #type proc(ssl: SSL, is_export: c.int, keylength: c.int) -> EC_KEY

@(default_calling_convention="c")
foreign lib {

    /* ssl control macros */
    DTLSv1_get_timeout :: proc(ssl: SSL, arg: rawptr) -> c.long ---
    DTLSv1_handle_timeout :: proc(ssl: SSL) -> c.long ---
    DTLSv1_listen :: proc(ssl: SSL, peer: rawptr) -> c.long ---
    
    SSL_session_reused :: proc(ssl: SSL) -> c.long ---
    SSL_num_renegotiations :: proc(ssl: SSL) -> c.long ---
    SSL_clear_num_renegotiations :: proc(ssl: SSL) -> c.long ---
    SSL_total_renegotiations :: proc(ssl: SSL) -> c.long ---

    SSL_CTX_need_tmp_RSA :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_set_tmp_rsa :: proc(ctx:SSL_CTX,rsa: cstring) -> c.long ---
    SSL_CTX_set_tmp_dh :: proc(ctx: SSL_CTX,dh: cstring) -> c.long ---
    SSL_CTX_set_tmp_ecdh :: proc(ctx: SSL_CTX,ecdh: cstring) -> c.long ---
    SSL_CTX_set_dh_auto :: proc(ctx:SSL_CTX, onoff: c.long) -> c.long ---
    SSL_CTX_set_ecdh_auto :: proc(ctx:SSL_CTX, onoff: c.long) -> c.long ---

    SSL_need_tmp_RSA :: proc(ssl: SSL) -> c.long ---
    SSL_set_tmp_rsa :: proc(ssl: SSL, rsa: cstring) -> c.long ---
    SSL_set_tmp_dh :: proc(ssl: SSL,dh: cstring) -> c.long ---
    SSL_set_tmp_ecdh :: proc(ssl: SSL, ecdh: cstring) -> c.long ---
    SSL_set_dh_auto :: proc(ssl: SSL, onoff: c.long) -> c.long ---
    SSL_set_ecdh_auto :: proc(ssl: SSL, onoff: c.long) -> c.long --- 

    SSL_CTX_set0_chain :: proc(ctx: SSL_CTX, chain: STACK_OF_X509) -> c.int ---
    SSL_CTX_set1_chain :: proc(ctx: SSL_CTX, chain: STACK_OF_X509) -> c.int ---
    SSL_CTX_add0_chain_cert :: proc(ctx: SSL_CTX, x509: X509) -> c.int ---
    SSL_CTX_add1_chain_cert :: proc(ctx: SSL_CTX, x509: X509) -> c.int ---
    SSL_CTX_get0_chain_certs :: proc( ctx: SSL_CTX, out_chain: STACK_OF_X509) -> c.int ---
    SSL_CTX_clear_chain_certs :: proc(ctx: SSL_CTX) -> c.int ---

    SSL_set0_chain :: proc(ssl: SSL, chain: STACK_OF_X509) -> c.int ---
    SSL_set1_chain :: proc(ssl: SSL, chain: STACK_OF_X509) -> c.int ---
    SSL_add0_chain_cert :: proc(ssl: SSL, x509: X509) -> c.int ---
    SSL_add1_chain_cert :: proc(ssl: SSL, x509: X509) -> c.int ---
    SSL_get0_chain_certs :: proc( ssl: SSL, out_chain: ^STACK_OF_X509) -> c.int ---
    SSL_clear_chain_certs :: proc(ssl: SSL) -> c.int ---

    SSL_CTX_set1_groups :: proc(ctx: SSL_CTX, groups: [^]c.int, groups_len: c.size_t) -> c.int ---
    SSL_CTX_set1_groups_list :: proc(ctx: SSL_CTX, groups: cstring) -> c.int ---

    SSL_set1_groups :: proc(ssl: SSL, groups: [^]c.int, groups_len: c.size_t) -> c.int ---
    SSL_set1_groups_list :: proc(ssl: SSL, groups: cstring) -> c.int ---
    
    SSL_CTX_get_min_proto_version :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_CTX_get_max_proto_version :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_CTX_set_min_proto_version :: proc(ctx: SSL_CTX, version: c.uint16_t) -> c.int ---
    SSL_CTX_set_max_proto_version :: proc(ctx: SSL_CTX, version: c.uint16_t) -> c.int ---
    
    SSL_get_min_proto_version :: proc(ssl: SSL) -> c.int ---
    SSL_get_max_proto_version :: proc(ssl: SSL) -> c.int ---
    SSL_set_min_proto_version :: proc(ssl: SSL, version: c.uint16_t) -> c.int ---
    SSL_set_max_proto_version :: proc(ssl: SSL, version: c.uint16_t) -> c.int ---

    SSL_CTX_get_ssl_method :: proc(ctx: SSL_CTX) -> SSL_METHOD ---


    SSL_CTX_add_extra_chain_cert :: proc(ctx: SSL_CTX, x509: cstring) -> c.int ---
    SSL_CTX_get_extra_chain_certs :: proc(ctx: SSL_CTX, px509: X509) -> c.int ---
    SSL_CTX_get_extra_chain_certs_only :: proc(ctx: SSL_CTX, px509: X509) -> c.int ---
    SSL_CTX_clear_extra_chain_certs :: proc(ctx: SSL_CTX) -> c.int ---
    
    SSL_get_shared_group :: proc(s: SSL, n: c.long) -> c.int ---
    
    SSL_get_server_tmp_key :: proc(s: SSL, pk: rawptr) -> c.int ---

    SSL_get_signature_nid :: proc(s: SSL, pn: rawptr) -> c.int ---
    SSL_get_peer_signature_nid :: proc(s: SSL, pn: rawptr) -> c.int ---
    SSL_get_peer_tmp_key :: proc(s: SSL, pk: rawptr) -> c.int ---


    BIO_f_ssl :: proc() -> BIO_METHOD ---
    BIO_new_ssl :: proc(ctx: SSL_CTX, client: c.int) -> BIO ---
    BIO_new_ssl_connect :: proc(ctx: SSL_CTX) -> BIO ---
    BIO_new_buffer_ssl_connect :: proc(ctx: SSL_CTX) -> BIO ---
    BIO_ssl_copy_session_id :: proc(to: BIO, from: BIO) -> c.int ---
    BIO_ssl_shutdown :: proc(ssl_bio: BIO) ---

    SSL_CTX_get_ciphers :: proc(ctx: SSL_CTX) -> STACK_OF_SSL_CIPHER ---
    SSL_CTX_set_cipher_list :: proc(ctx: SSL_CTX, str: cstring) -> c.int ---
    SSL_CTX_set_ciphersuites :: proc(ctx: SSL_CTX,str: cstring) -> c.int ---
    SSL_CTX_new :: proc(meth: SSL_METHOD) -> SSL_CTX ---
    SSL_CTX_free :: proc(ctx: SSL_CTX ) ---
    SSL_CTX_up_ref :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_CTX_set_timeout :: proc(ctx: SSL_CTX, t: c.long) -> c.long ---
    SSL_CTX_get_timeout :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_get_cert_store :: proc(ctx: SSL_CTX) -> X509_STORE ---
    SSL_CTX_set_cert_store :: proc(ctx: SSL_CTX, store: X509_STORE) ---
    SSL_CTX_set1_cert_store :: proc(ctx: SSL_CTX, store: X509_STORE) ---
    SSL_CTX_get0_certificate :: proc(ctx: SSL_CTX) -> X509 ---
    SSL_CTX_get0_privatekey :: proc(ctx: SSL_CTX) -> EVP_PKEY ---
    SSL_want :: proc(s: SSL) -> c.int ---
    SSL_clear :: proc(s: SSL) -> c.int ---

    SSL_CTX_flush_sessions :: proc(ctx: SSL_CTX, tm: c.long) ---

    SSL_get_current_cipher :: proc(s: SSL) -> SSL_CIPHER ---
    SSL_CIPHER_get_bits :: proc(ci: SSL_CIPHER, alg_bits: ^c.int) -> c.int ---
    SSL_CIPHER_get_version :: proc(ci: SSL_CIPHER) -> cstring ---
    SSL_CIPHER_get_name :: proc(ci: SSL_CIPHER) -> cstring ---
    SSL_CIPHER_get_id :: proc(ci: SSL_CIPHER) -> c.ulong ---
    SSL_CIPHER_get_value :: proc(ci: SSL_CIPHER) -> c.uint16_t ---
    SSL_CIPHER_find :: proc(ssl: SSL, ptr: [^]c.uchar) -> SSL_CIPHER ---
    SSL_CIPHER_get_cipher_nid :: proc(ci: SSL_CIPHER) -> c.int ---
    SSL_CIPHER_get_digest_nid :: proc(ci: SSL_CIPHER) -> c.int ---
    SSL_CIPHER_get_kx_nid :: proc(ci: SSL_CIPHER) -> c.int ---
    SSL_CIPHER_get_auth_nid :: proc(ci: SSL_CIPHER) -> c.int ---
    SSL_CIPHER_get_handshake_digest :: proc(ci: SSL_CIPHER) -> EVP_MD ---
    SSL_CIPHER_is_aead :: proc(ci: SSL_CIPHER) -> c.int ---

    SSL_get_fd :: proc( s: SSL) -> c.int ---
    SSL_get_rfd :: proc( s: SSL) -> c.int ---
    SSL_get_wfd :: proc( s: SSL) -> c.int ---
    SSL_get_cipher_list :: proc( s: SSL, n: c.int) -> cstring ---
    SSL_get_shared_ciphers :: proc( s: SSL, buf: [^]c.char, len: c.int) -> cstring ---
    SSL_get_read_ahead :: proc(s: SSL) -> c.int ---
    SSL_pending :: proc( s: SSL) -> c.int ---
    SSL_set_fd :: proc(s: SSL, fd: c.int) -> c.int ---
    SSL_set_rfd :: proc(s: SSL, fd: c.int) -> c.int ---
    SSL_set_wfd :: proc(s: SSL, fd: c.int) -> c.int ---
    SSL_set_bio :: proc(s: SSL, rbio: BIO, wbio: BIO) ---
    SSL_get_rbio :: proc( s: SSL) -> BIO ---
    SSL_set0_rbio :: proc(s: SSL, rbio: BIO) ---
    SSL_get_wbio :: proc( s: SSL) -> BIO ---
    SSL_set_cipher_list :: proc(s: SSL, str: cstring) -> c.int ---
    SSL_set_ciphersuites :: proc(s: SSL, str: cstring) -> int ---
    SSL_set_read_ahead :: proc(s: SSL, yes: c.int) ---
    SSL_get_verify_mode :: proc( s: SSL) -> c.int ---
    SSL_get_verify_depth :: proc(s: SSL) -> c.int ---
    SSL_get_verify_callback :: proc( s: SSL) -> SSL_verify_callback  ---
    SSL_set_verify :: proc(s: SSL, mode: c.int, callback: SSL_verify_callback) ---
    SSL_set_verify_depth :: proc(s: SSL, depth: c.int) ---
    SSL_use_RSAPrivateKey :: proc(ssl: SSL, rsa: RSA) -> c.int ---
    SSL_use_RSAPrivateKey_ASN1 :: proc(ssl: SSL, d: cstring, len: c.long) -> c.int ---
    SSL_use_PrivateKey :: proc(ssl: SSL, pkey: EVP_PKEY) -> c.int ---
    SSL_use_PrivateKey_ASN1 :: proc(pk: c.int, ssl: SSL, d: cstring, len: c.long) -> c.int ---
    SSL_use_certificate :: proc(ssl: SSL, x: X509) -> c.int ---
    SSL_use_certificate_ASN1 :: proc(ssl: SSL, d: cstring, len: c.int) -> c.int ---

    SSL_use_RSAPrivateKey_file :: proc(ssl: SSL, file: cstring, type: c.int) -> c.int ---
    SSL_use_PrivateKey_file :: proc(ssl: SSL, file: cstring, type: c.int) -> c.int ---
    SSL_use_certificate_file :: proc(ssl: SSL, file: cstring, type: c.int) -> c.int ---
    SSL_use_certificate_chain_file :: proc(ssl: SSL, file: cstring) -> c.int ---
    SSL_CTX_use_RSAPrivateKey_file :: proc(ctx: SSL_CTX, file: cstring, type: c.int) -> c.int ---
    SSL_CTX_use_PrivateKey_file :: proc(ctx: SSL_CTX, file: cstring, type: c.int) -> c.int ---
    SSL_CTX_use_certificate_file :: proc(ctx: SSL_CTX, file: cstring, type: c.int) -> c.int ---
    SSL_CTX_use_certificate_chain_file :: proc(ctx: SSL_CTX, file: cstring) -> c.int --- /* PEM type */
    SSL_CTX_use_certificate_chain_mem :: proc(ctx: SSL_CTX, buf: rawptr, len: c.int) -> c.int ---

    SSL_load_client_CA_file :: proc(file: cstring) -> STACK_OF_X509_NAME ---
    SSL_add_file_cert_subjects_to_stack :: proc(stackCAs: STACK_OF_X509_NAME, file: cstring) -> c.int ---
    SSL_add_dir_cert_subjects_to_stack :: proc(stackCAs: STACK_OF_X509_NAME , dir: cstring) -> c.int ---

    SSL_load_error_strings :: proc() ---
    SSL_state_string :: proc(ssl: SSL) -> cstring ---
    SSL_rstate_string :: proc(ssl: SSL) -> cstring ---
    SSL_state_string_long :: proc(ssl: SSL) -> cstring ---
    SSL_rstate_string_long :: proc(ssl: SSL) -> cstring ---
    SSL_SESSION_get0_cipher :: proc(ss: SSL_SESSION) -> SSL_CIPHER ---
    SSL_SESSION_get_master_key :: proc(ss: SSL_SESSION, out: [^]c.uchar, max_out: c.size_t) -> c.size_t ---
    SSL_SESSION_get_protocol_version :: proc(s: SSL_SESSION) -> c.int ---
    SSL_SESSION_get_time :: proc(s: SSL_SESSION) -> c.long ---
    SSL_SESSION_set_time :: proc(s: SSL_SESSION, t: c.long) -> c.long ---
    SSL_SESSION_get_timeout :: proc(s: SSL_SESSION) -> c.long ---
    SSL_SESSION_set_timeout :: proc(s: SSL_SESSION, t: c.long) -> c.long ---
    SSL_copy_session_id :: proc(to: SSL, from: SSL) -> c.int ---
    SSL_SESSION_get0_peer :: proc(s: SSL_SESSION) -> X509 ---
    SSL_SESSION_set1_id :: proc(s: SSL_SESSION, sid: [^]c.uchar, sid_len: c.uint) -> int ---
    SSL_SESSION_set1_id_context :: proc(s: SSL_SESSION, sid_ctx: [^]c.uchar, sid_ctx_len: c.uint) -> int ---
    SSL_SESSION_is_resumable :: proc(s: SSL_SESSION) -> c.int ---

    SSL_SESSION_new :: proc() -> SSL_SESSION ---
    SSL_SESSION_free :: proc(ses: SSL_SESSION) ---
    SSL_SESSION_up_ref :: proc(ss: SSL_SESSION) -> c.int ---
    SSL_SESSION_get_id :: proc(ss: SSL_SESSION, len: c.uint) -> [^]c.uchar ---
    SSL_SESSION_get0_id_context :: proc(ss: SSL_SESSION, len: c.uint) -> [^]c.uchar ---
    SSL_SESSION_get_max_early_data :: proc(sess: SSL_SESSION) -> c.uint32_t ---
    SSL_SESSION_set_max_early_data :: proc(sess: SSL_SESSION, max_early_data: c.uint32_t) -> c.int ---
    SSL_SESSION_get_ticket_lifetime_hint :: proc(s: SSL_SESSION) -> c.ulong ---
    SSL_SESSION_has_ticket :: proc(s: SSL_SESSION) -> c.int ---
    SSL_SESSION_get_compress_id :: proc(ss: SSL_SESSION) -> c.uint ---
    SSL_SESSION_print_fp :: proc(fp: FILE, ses: SSL_SESSION) -> c.int ---
    SSL_SESSION_print :: proc(fp: BIO, ses: SSL_SESSION) -> c.int ---
    i2d_SSL_SESSION :: proc(input: SSL_SESSION, pp: ^[^]c.uchar) -> c.int ---
    SSL_set_session :: proc(to: SSL, session: SSL_SESSION) -> c.int ---
    SSL_CTX_add_session :: proc(s: SSL_CTX, ci: SSL_SESSION) -> c.int ---
    SSL_CTX_remove_session :: proc(s: SSL_CTX, ci: SSL_SESSION) -> c.int ---
    SSL_CTX_set_generate_session_id :: proc(s: SSL_CTX, cb: GEN_SESSION_CB) -> c.int ---
    SSL_set_generate_session_id :: proc(s: SSL, cb: GEN_SESSION_CB) -> c.int ---
    SSL_has_matching_session_id :: proc(ssl: SSL, id: [^]c.uchar, id_len: c.uint) -> c.int ---
    d2i_SSL_SESSION :: proc(a: ^SSL_SESSION, pp: ^[^]c.uchar, length: c.long) -> SSL_SESSION ---

    SSL_get_peer_certificate :: proc(s: SSL) -> X509 ---

    SSL_get_peer_cert_chain :: proc(s: SSL) -> STACK_OF_X509 ---

    SSL_CTX_get_verify_mode :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_CTX_get_verify_depth :: proc(ctx: SSL_CTX) -> c.int ---
    
    SSL_CTX_get_verify_callback :: proc(ctx: SSL_CTX) -> SSL_verify_callback ---
    SSL_CTX_set_verify :: proc(ctx: SSL_CTX, mode: c.int, callback: SSL_verify_callback) ---
    SSL_CTX_set_verify_depth :: proc(ctx: SSL_CTX, depth: c.int) ---

    SSL_CTX_set_cert_verify_callback :: proc(ctx: SSL_CTX, cb: SSL_cert_verify_callback, arg: rawptr) ---
    SSL_CTX_use_RSAPrivateKey :: proc(ctx: SSL_CTX, rsa: RSA) -> c.int ---
    SSL_CTX_use_RSAPrivateKey_ASN1 :: proc(ctx: SSL_CTX,  d: [^]c.uchar, len: c.long) -> c.int ---
    SSL_CTX_use_PrivateKey :: proc(ctx: SSL_CTX, pkey: EVP_PKEY) -> c.int ---
    SSL_CTX_use_PrivateKey_ASN1 :: proc(pk: int, ctx: SSL_CTX,  d: [^]c.uchar, len: c.long) -> c.int ---
    SSL_CTX_use_certificate :: proc(ctx: SSL_CTX, x: X509) -> c.int ---
    SSL_CTX_use_certificate_ASN1 :: proc(ctx: SSL_CTX, len: c.int,  d: [^]c.uchar) -> c.int ---

    SSL_CTX_get_default_passwd_cb :: proc(ctx: SSL_CTX) -> pem_password_cb ---
    SSL_CTX_set_default_passwd_cb :: proc(ctx: SSL_CTX, cb: pem_password_cb) ---
    SSL_CTX_get_default_passwd_cb_userdata :: proc(ctx: SSL_CTX) -> rawptr ---
    SSL_CTX_set_default_passwd_cb_userdata :: proc(ctx: SSL_CTX, u: rawptr) ---

    SSL_CTX_check_private_key :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_check_private_key :: proc(ssl: SSL) -> c.int --- /* ssl.h is bad with naming consistency:: param was ctx in file*/

    SSL_CTX_set_session_id_context :: proc(ctx: SSL_CTX,  sid_ctx: [^]c.uchar, sid_ctx_len: c.uint) -> c.int ---

    SSL_set_session_id_context :: proc(ssl: SSL,  sid_ctx: [^]c.uchar, sid_ctx_len: c.uint) -> c.int ---

    SSL_CTX_set_purpose :: proc(s: SSL_CTX, purpose: c.int) -> c.int ---
    SSL_set_purpose :: proc(s: SSL, purpose: c.int) -> c.int ---
    SSL_CTX_set_trust :: proc(s: SSL_CTX, trust: c.int) -> c.int ---
    SSL_set_trust :: proc(s: SSL, trust: c.int) -> c.int ---
    SSL_set1_host :: proc(s: SSL,  hostname: cstring) -> c.int ---
    SSL_set_hostflags :: proc(s: SSL, flags: c.uint) ---
    SSL_get0_peername :: proc(s: SSL) -> cstring ---

    SSL_CTX_get0_param :: proc(ctx: SSL_CTX) -> X509_VERIFY_PARAM ---
    SSL_CTX_set1_param :: proc(ctx: SSL_CTX, vpm: X509_VERIFY_PARAM) -> c.int ---
    SSL_get0_param :: proc(ssl: SSL) -> X509_VERIFY_PARAM ---
    SSL_set1_param :: proc(ssl: SSL, vpm: X509_VERIFY_PARAM) -> c.int ---

    SSL_new :: proc(ctx: SSL_CTX) -> SSL ---
    SSL_free :: proc(ssl: SSL) ---
    SSL_up_ref :: proc(ssl: SSL) -> c.int ---
    SSL_accept :: proc(ssl: SSL) -> c.int ---
    SSL_connect :: proc(ssl: SSL) -> c.int ---
    SSL_is_dtls :: proc(s: SSL) -> c.int ---
    SSL_is_server :: proc(s: SSL) -> c.int ---
    SSL_read :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
    SSL_peek :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
    SSL_write :: proc(ssl: SSL, buf: rawptr, num: c.int) -> c.int ---
    SSL_read_ex :: proc(ssl: SSL, buf: rawptr, num: c.size_t, bytes_read: ^c.size_t) -> c.int ---
    SSL_peek_ex :: proc(ssl: SSL, buf: rawptr, num: c.size_t, bytes_peeked: ^c.size_t) -> c.int ---
    SSL_write_ex :: proc(ssl: SSL, buf: rawptr, num: c.size_t, bytes_written: ^c.size_t) -> c.int ---

    SSL_CTX_get_max_early_data :: proc(ctx: SSL_CTX) -> c.uint32_t ---
    SSL_CTX_set_max_early_data :: proc(ctx: SSL_CTX, max_early_data: c.uint32_t) -> c.int ---
    
    SSL_get_max_early_data :: proc(s: SSL) -> c.uint32_t ---
    SSL_set_max_early_data :: proc(s: SSL, max_early_data: c.uint32_t) -> c.int ---
    
    SSL_get_early_data_status :: proc(s: SSL) -> c.int ---
    
    SSL_read_early_data :: proc(s: SSL, buf: rawptr, num: c.size_t, readbytes: ^c.size_t) -> c.int ---
    SSL_write_early_data :: proc(s: SSL,  buf: rawptr, num: c.size_t, written: ^c.size_t) -> c.int ---

    SSL_ctrl :: proc(ssl: SSL, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
    SSL_callback_ctrl :: proc(s: SSL, n: int, cb: SSL_void_callback) -> c.long ---
    SSL_CTX_ctrl :: proc(ctx: SSL_CTX, cmd: c.int, larg: c.long, parg: rawptr) -> c.long ---
    SSL_CTX_callback_ctrl :: proc(ctx: SSL_CTX, n: int, cb: SSL_void_callback) -> c.long ---

    SSL_get_error :: proc(s: SSL, ret_code: c.int) -> c.int ---
    SSL_get_version :: proc(s: SSL) -> cstring ---

    /* This sets the 'default' SSL version that SSL_new :: proc() will create */
    SSL_CTX_set_ssl_version :: proc(ctx: SSL_CTX, meth: SSL_METHOD) -> c.int ---

    SSLv23_method :: proc() -> SSL_METHOD ---		/* SSLv3 or TLSv1.* */
    SSLv23_server_method :: proc() -> SSL_METHOD ---	/* SSLv3 or TLSv1.* */
    SSLv23_client_method :: proc() -> SSL_METHOD ---	/* SSLv3 or TLSv1.* */
    
    TLSv1_method :: proc() -> SSL_METHOD ---		/* TLSv1.0 */
    TLSv1_server_method :: proc() -> SSL_METHOD ---	/* TLSv1.0 */
    TLSv1_client_method :: proc() -> SSL_METHOD ---	/* TLSv1.0 */
    
    TLSv1_1_method :: proc() -> SSL_METHOD ---		/* TLSv1.1 */
    TLSv1_1_server_method :: proc() -> SSL_METHOD ---	/* TLSv1.1 */
    TLSv1_1_client_method :: proc() -> SSL_METHOD ---	/* TLSv1.1 */
    
    TLSv1_2_method :: proc() -> SSL_METHOD ---		/* TLSv1.2 */
    TLSv1_2_server_method :: proc() -> SSL_METHOD ---	/* TLSv1.2 */
    TLSv1_2_client_method :: proc() -> SSL_METHOD ---	/* TLSv1.2 */
    
    TLS_method :: proc() -> SSL_METHOD ---		/* TLS v1.0 or later */
    TLS_server_method :: proc() -> SSL_METHOD ---	/* TLS v1.0 or later */
    TLS_client_method :: proc() -> SSL_METHOD ---	/* TLS v1.0 or later */
    
    DTLSv1_method :: proc() -> SSL_METHOD ---		/* DTLSv1.0 */
    DTLSv1_server_method :: proc() -> SSL_METHOD ---	/* DTLSv1.0 */
    DTLSv1_client_method :: proc() -> SSL_METHOD ---	/* DTLSv1.0 */
    
    DTLSv1_2_method :: proc() -> SSL_METHOD ---	        /* DTLSv1.2 */
    DTLSv1_2_server_method :: proc() -> SSL_METHOD ---	/* DTLSv1.2 */
    DTLSv1_2_client_method :: proc() -> SSL_METHOD ---	/* DTLSv1.2 */
    
    DTLS_method :: proc() -> SSL_METHOD ---		/* DTLS v1.0 or later */
    DTLS_server_method :: proc() -> SSL_METHOD ---	/* DTLS v1.0 or later */
    DTLS_client_method :: proc() -> SSL_METHOD ---	/* DTLS v1.0 or later */
    
    SSL_get_ciphers :: proc(s: SSL) -> STACK_OF_SSL_CIPHER ---
    SSL_get_client_ciphers :: proc(s: SSL) -> STACK_OF_SSL_CIPHER ---
    SSL_get1_supported_ciphers :: proc(s: SSL) -> STACK_OF_SSL_CIPHER ---

    SSL_do_handshake :: proc(s: SSL) -> c.int ---
    SSL_renegotiate :: proc(s: SSL) -> c.int ---
    SSL_renegotiate_abbreviated :: proc(s: SSL) -> c.int ---
    SSL_renegotiate_pending :: proc(s: SSL) -> c.int ---
    SSL_shutdown :: proc(s: SSL) -> c.int ---

    SSL_get_ssl_method :: proc(s: SSL) -> SSL_METHOD ---
    SSL_set_ssl_method :: proc(s: SSL, method: SSL_METHOD) -> c.int ---
    SSL_alert_type_string_long :: proc(value: c.int) -> cstring ---
    SSL_alert_type_string :: proc(value: c.int) -> cstring ---
    SSL_alert_desc_string_long :: proc(value: c.int) -> cstring --- /* WHY is this an int an not a long? */
    SSL_alert_desc_string :: proc(value: c.int) -> cstring ---

    SSL_set_client_CA_list :: proc(s: SSL, name_list: STACK_OF_X509_NAME) ---
    SSL_CTX_set_client_CA_list :: proc(ctx: SSL_CTX, name_list: STACK_OF_X509_NAME) ---
    SSL_get_client_CA_list :: proc(s: SSL) -> STACK_OF_X509_NAME ---
    SSL_CTX_get_client_CA_list :: proc(s: SSL_CTX) -> STACK_OF_X509_NAME ---
    SSL_add_client_CA :: proc(ssl: SSL, x: X509) -> c.int ---
    SSL_CTX_add_client_CA :: proc(ctx: SSL_CTX, x: X509) -> c.int ---

    SSL_set_connect_state :: proc(s: SSL) ---
    SSL_set_accept_state :: proc(s: SSL) ---

    SSL_get_default_timeout :: proc(s: SSL) -> c.long ---

    SSL_CIPHER_description :: proc(cipher: SSL_CIPHER, buf: cstring, size: c.int) -> cstring ---
    SSL_dup_CA_list :: proc(sk: STACK_OF_X509_NAME) -> STACK_OF_X509_NAME ---

    SSL_dup :: proc(ssl: SSL) -> SSL ---

    SSL_get_certificate :: proc(ssl: SSL) -> X509 ---
    SSL_get_privatekey :: proc(ssl: SSL) -> EVP_PKEY --- /* EVP_PKEY */ 

    SSL_CTX_set_quiet_shutdown :: proc(ctx: SSL_CTX, mode: c.int) ---
    SSL_CTX_get_quiet_shutdown :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_set_quiet_shutdown :: proc(ssl: SSL, mode: c.int) ---
    SSL_get_quiet_shutdown :: proc(ssl: SSL) -> c.int ---
    SSL_set_shutdown :: proc(ssl: SSL, mode: c.int) ---
    SSL_get_shutdown :: proc(ssl: SSL) -> c.int ---
    SSL_version :: proc(ssl: SSL) -> c.int ---
    SSL_CTX_set_default_verify_paths :: proc(ctx: SSL_CTX) -> c.int ---
    SSL_CTX_load_verify_locations :: proc(ctx: SSL_CTX, CAfile: cstring, CApath: cstring) -> c.int ---
    SSL_CTX_load_verify_mem :: proc(ctx: SSL_CTX, buf: rawptr, len: c.int) -> c.int ---

    SSL_get_session :: proc(ssl: SSL) -> SSL_SESSION ---
    SSL_get1_session :: proc(ssl: SSL) -> SSL_SESSION --- /* obtain a reference count */
    SSL_get_SSL_CTX :: proc(ssl: SSL) -> SSL_CTX ---
    SSL_set_SSL_CTX :: proc(ssl: SSL, ctx: SSL_CTX) -> SSL_CTX ---

    SSL_set_info_callback :: proc(ssl: SSL, cb: SSL_info_callback) ---
    SSL_get_info_callback :: proc(ssl: SSL) -> SSL_info_callback ---
    SSL_state :: proc(ssl: SSL) -> c.int ---
    SSL_set_state :: proc(ssl: SSL, state: c.int) ---

    SSL_set_verify_result :: proc(ssl: SSL, v: c.long) ---
    SSL_get_verify_result :: proc(ssl: SSL) -> c.long ---

    SSL_set_ex_data :: proc(ssl: SSL, idx: c.int, data: rawptr) -> c.int ---
    SSL_get_ex_data :: proc(ssl: SSL, idx: c.int) -> rawptr ---
    SSL_get_ex_new_index :: proc(argl: c.long, argp: rawptr, new_func: CRYPTO_EX_new,
				 dup_func: CRYPTO_EX_dup, free_func: CRYPTO_EX_free) -> c.int ---

    SSL_SESSION_set_ex_data :: proc(ss: SSL_SESSION, idx: c.int, data: rawptr) -> c.int ---
    SSL_SESSION_get_ex_data :: proc(ss: SSL_SESSION, idx: c.int) -> rawptr ---
    SSL_SESSION_get_ex_new_index :: proc(argl: c.long , argp: rawptr,
					 new_func: CRYPTO_EX_new, dup_func: CRYPTO_EX_dup,
					 free_func: CRYPTO_EX_free) -> c.int ---

    SSL_CTX_set_ex_data :: proc(ssl: SSL_CTX, idx: c.int, data: rawptr) -> c.int ---
    SSL_CTX_get_ex_data :: proc(ssl: SSL_CTX, idx: int) -> rawptr ---
    SSL_CTX_get_ex_new_index :: proc(argl: c.long, argp: rawptr, new_func: CRYPTO_EX_new,
				     dup_func: CRYPTO_EX_dup, free_func: CRYPTO_EX_free) -> c.int ---

    SSL_get_ex_data_X509_STORE_CTX_idx :: proc() -> c.int ---

    SSL_CTX_sess_set_cache_size :: proc(ctx: SSL_CTX,t: c.long) -> c.long ---
    SSL_CTX_sess_get_cache_size :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_set_session_cache_mode :: proc(ctx: SSL_CTX, m: c.long) -> c.long ---
    SSL_CTX_get_session_cache_mode :: proc(ctx: SSL_CTX) -> c.long ---

    SSL_CTX_get_default_read_ahead :: proc(ctx: SSL_CTX) -> c.long---
    SSL_CTX_set_default_read_ahead :: proc(ctx: SSL_CTX, m: c.long) ---
    SSL_CTX_get_read_ahead :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_set_read_ahead :: proc(ctx: SSL_CTX, m: c.long) -> c.long ---
    SSL_CTX_get_max_cert_list :: proc(ctx: SSL_CTX) -> c.long ---
    SSL_CTX_set_max_cert_list :: proc(ctx: SSL_CTX, m: c.long) -> c.long ---
    SSL_get_max_cert_list :: proc(ssl: SSL) -> c.long ---
    SSL_set_max_cert_list :: proc(ssl: SSL, m: c.long) -> c.long ---

    SSL_CTX_set_max_send_fragment :: proc(ctx: SSL_CTX, m: c.long) -> c.long ---
    SSL_set_max_send_fragment :: proc(ssl: SSL, m: c.long) -> c.long ---

    /* NB: the keylength is only applicable when is_export is true */
    SSL_CTX_set_tmp_rsa_callback :: proc(ctx: SSL_CTX, cb: SSL_tmp_RSA_callback) ---
    SSL_set_tmp_rsa_callback :: proc(ssl: SSL, cb: SSL_tmp_RSA_callback) ---

    SSL_CTX_set_tmp_dh_callback :: proc(ctx: SSL_CTX, dh: SSL_tmp_DH_callback) ---
    SSL_set_tmp_dh_callback :: proc(ssl: SSL, cb: SSL_tmp_DH_callback) ---

    SSL_CTX_set_tmp_ecdh_callback :: proc(ctx: SSL_CTX , ecdh: SSL_tmp_ECDH_callback) ---
    SSL_set_tmp_ecdh_callback :: proc(ssl: SSL, ecdh: SSL_tmp_ECDH_callback) ---

    SSL_get_client_random  :: proc(s: SSL, out: [^]c.uchar, max_out: c.size_t) -> c.size_t ---
    SSL_get_server_random  :: proc(s: SSL, out: [^]c.uchar, max_out: c.size_t) -> c.size_t ---

    SSL_get_current_compression :: proc(s: SSL) -> rawptr ---
    SSL_get_current_expansion :: proc(s: SSL) -> rawptr ---

    SSL_COMP_get_name :: proc(comp: rawptr) -> cstring ---
    SSL_COMP_get_compression_methods :: proc() -> rawptr ---

/* TLS extensions functions */
    SSL_set_session_ticket_ext :: proc(s: SSL, ext_data: rawptr, ext_len: c.int) -> c.int ---

    SSL_set_session_ticket_ext_cb :: proc(s: SSL, cb: tls_session_ticket_ext_cb_fn, arg: rawptr) -> c.int ---

/* Pre-shared secret session resumption functions */
    SSL_set_session_secret_cb :: proc(s: SSL, tls_session_secret_cb: tls_session_secret_cb_fn, arg: rawptr) -> c.int ---

    SSL_cache_hit :: proc(s: SSL) -> c.int ---

    SSL_set_security_level :: proc(ssl: SSL, level: c.int) ---
    SSL_get_security_level :: proc(ssl:  SSL) -> c.int ---
    
    SSL_CTX_set_security_level :: proc(ctx: SSL_CTX, level: c.int) ---
    SSL_CTX_get_security_level :: proc(ctx: SSL_CTX) -> c.int ---
}


/* What the "other" parameter contains in security callback */
/* Mask for type */
SSL_SECOP_OTHER_TYPE :: 0xffff0000
SSL_SECOP_OTHER_NONE :: 0
SSL_SECOP_OTHER_CIPHER :: 1 << 16
SSL_SECOP_OTHER_CURVE :: 2 << 16
SSL_SECOP_OTHER_DH :: 3 << 16
SSL_SECOP_OTHER_PKEY :: 4 << 16
SSL_SECOP_OTHER_SIGALG :: 5 << 16
SSL_SECOP_OTHER_CERT :: 6 << 16

/* Indicated operation refers to peer key or certificate */
SSL_SECOP_PEER :: 0x1000

/* Values for "op" parameter in security callback */

/* Called to filter ciphers */
/* Ciphers client supports */
SSL_SECOP_CIPHER_SUPPORTED :: 1 | SSL_SECOP_OTHER_CIPHER
/* Cipher shared by client/server */
SSL_SECOP_CIPHER_SHARED :: 2 | SSL_SECOP_OTHER_CIPHER
/* Sanity check of cipher server selects */
SSL_SECOP_CIPHER_CHECK :: 3 | SSL_SECOP_OTHER_CIPHER
/* Curves supported by client */
SSL_SECOP_CURVE_SUPPORTED :: 4 | SSL_SECOP_OTHER_CURVE
/* Curves shared by client/server */
SSL_SECOP_CURVE_SHARED :: 5 | SSL_SECOP_OTHER_CURVE
/* Sanity check of curve server selects */
SSL_SECOP_CURVE_CHECK :: 6 | SSL_SECOP_OTHER_CURVE
/* Temporary DH key */
/*
 * XXX: changed in OpenSSL e2b420fdd70 to 7 | SSL_SECOP_OTHER_PKEY
 * Needs switching internal use of DH to EVP_PKEY. The code is not reachable
 * from outside the library as long as we do not expose the callback in the API.
 */
SSL_SECOP_TMP_DH :: 7 | SSL_SECOP_OTHER_DH
/* SSL/TLS version */
SSL_SECOP_VERSION :: 9 | SSL_SECOP_OTHER_NONE
/* Session tickets */
SSL_SECOP_TICKET :: 10 | SSL_SECOP_OTHER_NONE
/* Supported signature algorithms sent to peer */
SSL_SECOP_SIGALG_SUPPORTED :: 11 | SSL_SECOP_OTHER_SIGALG
/* Shared signature algorithm */
SSL_SECOP_SIGALG_SHARED :: 12 | SSL_SECOP_OTHER_SIGALG
/* Sanity check signature algorithm allowed */
SSL_SECOP_SIGALG_CHECK :: 13 | SSL_SECOP_OTHER_SIGALG
/* Used to get mask of supported public key signature algorithms */
SSL_SECOP_SIGALG_MASK :: 14 | SSL_SECOP_OTHER_SIGALG
/* Use to see if compression is allowed */
SSL_SECOP_COMPRESSION :: 15 | SSL_SECOP_OTHER_NONE
/* EE key in certificate */
SSL_SECOP_EE_KEY :: 16 | SSL_SECOP_OTHER_CERT
/* CA key in certificate */
SSL_SECOP_CA_KEY :: 17 | SSL_SECOP_OTHER_CERT
/* CA digest algorithm in certificate */
SSL_SECOP_CA_MD :: 18 | SSL_SECOP_OTHER_CERT
/* Peer EE key in certificate */
SSL_SECOP_PEER_EE_KEY :: SSL_SECOP_EE_KEY | SSL_SECOP_PEER
/* Peer CA key in certificate */
SSL_SECOP_PEER_CA_KEY :: SSL_SECOP_CA_KEY | SSL_SECOP_PEER
/* Peer CA digest algorithm in certificate */
SSL_SECOP_PEER_CA_MD :: SSL_SECOP_CA_MD | SSL_SECOP_PEER

    /*
         * QUIC integration.
         *
         * QUIC acts as an underlying transport for the TLS 1.3 handshake. The following
         * functions allow a QUIC implementation to serve as the underlying transport as
         * described in RFC 9001.
         *
         * When configured for QUIC, |SSL_do_handshake| will drive the handshake as
         * before, but it will not use the configured |BIO|. It will call functions on
         * |SSL_QUIC_METHOD| to configure secrets and send data. If data is needed from
         * the peer, it will return |SSL_ERROR_WANT_READ|. As the caller receives data
         * it can decrypt, it calls |SSL_provide_quic_data|. Subsequent
         * |SSL_do_handshake| calls will then consume that data and progress the
         * handshake. After the handshake is complete, the caller should continue to
         * call |SSL_provide_quic_data| for any post-handshake data, followed by
         * |SSL_process_quic_post_handshake| to process it. It is an error to call
         * |SSL_peek|, |SSL_read| and |SSL_write| in QUIC.
         *
         * To avoid DoS attacks, the QUIC implementation must limit the amount of data
         * being queued up. The implementation can call
         * |SSL_quic_max_handshake_flight_len| to get the maximum buffer length at each
         * encryption level.
         *
         * QUIC implementations must additionally configure transport parameters with
         * |SSL_set_quic_transport_params|. |SSL_get_peer_quic_transport_params| may be
         * used to query the value received from the peer. This extension is handled
         * as an opaque byte string, which the caller is responsible for serializing
         * and parsing. See RFC 9000 section 7.4 for further details.
         */
        
        /*
         * ssl_encryption_level_t specifies the QUIC encryption level used to transmit
         * handshake messages.
         */
    ssl_encryption_level_t :: enum {
	ssl_encryption_initial = 0,
	ssl_encryption_early_data,
	ssl_encryption_handshake,
	ssl_encryption_application,
    }
    OSSL_ENCRYPTION_LEVEL :: ssl_encryption_level_t /* NOT distinct, they are the same type */

	/*
         * ssl_quic_method_st (aka |SSL_QUIC_METHOD|) describes custom QUIC hooks.
         *
         * Note that we provide both the new (BoringSSL) secrets interface
         * (set_read_secret/set_write_secret) along with the old interface
         * (set_encryption_secrets), which quictls is still using.
         *
         * Since some consumers fail to use named initialisers, the order of these
         * functions is important. Hopefully all of these consumers use the old version.
         */
    SSL_QUIC_METHOD :: struct {
	    /*
   	     * set_encryption_secrets configures the read and write secrets for the
   	     * given encryption level. This function will always be called before an
   	     * encryption level other than |ssl_encryption_initial| is used.
   	     *
   	     * When reading packets at a given level, the QUIC implementation must
   	     * send ACKs at the same level, so this function provides read and write
   	     * secrets together. The exception is |ssl_encryption_early_data|, where
   	     * secrets are only available in the client to server direction. The
   	     * other secret will be NULL. The server acknowledges such data at
   	     * |ssl_encryption_application|, which will be configured in the same
   	     * |SSL_do_handshake| call.
   	     *
   	     * This function should use |SSL_get_current_cipher| to determine the TLS
   	     * cipher suite.
   	     */
	set_encryption_secrets: #type proc "c"(ssl: SSL,
					   level: ssl_encryption_level_t ,
					   read_secret: [^]c.uint8_t,
					   write_secret: [^]c.uint8_t,
					   secret_len: c.size_t) -> c.int,

	    /*
	     * add_handshake_data adds handshake data to the current flight at the
	     * given encryption level. It returns one on success and zero on error.
	     * Callers should defer writing data to the network until |flush_flight|
	     * to better pack QUIC packets into transport datagrams.
	     *
	     * If |level| is not |ssl_encryption_initial|, this function will not be
	     * called before |level| is initialized with |set_write_secret|.
	     */
	add_handshake_data: #type proc "c"(ssl: SSL,
				       level: ssl_encryption_level_t,
				       data: [^]c.uint8_t,
				       len: c.size_t) -> c.int,

	    /*
	     * flush_flight is called when the current flight is complete and should
	     * be written to the transport. Note a flight may contain data at
	     * several encryption levels. It returns one on success and zero on
	     * error.
	     */
	flush_flight: #type proc "c"(ssl: SSL) -> c.int,

	    /*
	     * send_alert sends a fatal alert at the specified encryption level. It
	     * returns one on success and zero on error.
	     *
	     * If |level| is not |ssl_encryption_initial|, this function will not be
	     * called before |level| is initialized with |set_write_secret|.
	     */
	send_alert: #type proc "c"(ssl: SSL,
			       level: ssl_encryption_level_t,
			       alert: c.uint8_t) -> c.int,

	    /*
	     * set_read_secret configures the read secret and cipher suite for the
	     * given encryption level. It returns one on success and zero to
	     * terminate the handshake with an error. It will be called at most once
	     * per encryption level.
	     *
	     * Read keys will not be released before QUIC may use them. Once a level
	     * has been initialized, QUIC may begin processing data from it.
	     * Handshake data should be passed to |SSL_provide_quic_data| and
	     * application data (if |level| is |ssl_encryption_early_data| or
	     * |ssl_encryption_application|) may be processed according to the rules
	     * of the QUIC protocol.
	     */
	set_read_secret: #type proc "c"(ssl: SSL,
				    level: ssl_encryption_level_t,
				    cipher: SSL_CIPHER,
				    secret: [^]c.uint8_t,
				    secret_len: c.size_t) -> c.int,

	    /*
	     * set_write_secret behaves like |set_read_secret| but configures the
	     * write secret and cipher suite for the given encryption level. It will
	     * be called at most once per encryption level.
	     *
	     * Write keys will not be released before QUIC may use them. If |level|
	     * is |ssl_encryption_early_data| or |ssl_encryption_application|, QUIC
	     * may begin sending application data at |level|.
	     */
	set_write_secret: #type proc "c"(ssl: SSL,
				     level: ssl_encryption_level_t,
				     cipher: SSL_CIPHER,
				     secret: [^]c.uint8_t ,
				     secret_len: c.size_t) -> c.int
    }

@(default_calling_convention="c")
foreign lib {

        /*
         * SSL_CTX_set_quic_method configures the QUIC hooks. This should only be
         * configured with a minimum version of TLS 1.3. |quic_method| must remain valid
         * for the lifetime of |ctx|. It returns one on success and zero on error.
         */
    SSL_CTX_set_quic_method :: proc(ctx: SSL_CTX, quic_method: ^SSL_QUIC_METHOD) -> c.int ---

        /*
         * SSL_set_quic_method configures the QUIC hooks. This should only be
         * configured with a minimum version of TLS 1.3. |quic_method| must remain valid
         * for the lifetime of |ssl|. It returns one on success and zero on error.
         */
    SSL_set_quic_method :: proc(ssl: SSL, quic_method: ^SSL_QUIC_METHOD) -> c.int ---

	/* SSL_is_quic returns true if an SSL has been configured for use with QUIC. */
    SSL_is_quic :: proc(ssl: SSL) -> c.int ---

	/*
         * SSL_quic_max_handshake_flight_len returns returns the maximum number of bytes
         * that may be received at the given encryption level. This function should be
         * used to limit buffering in the QUIC implementation. See RFC 9000 section 7.5.
         */
    SSL_quic_max_handshake_flight_len :: proc(ssl: SSL, level: ssl_encryption_level_t) -> c.size_t ---

        /*
         * SSL_quic_read_level returns the current read encryption level.
         */
    SSL_quic_read_level :: proc(ssl: SSL) -> ssl_encryption_level_t ---

	/*
         * SSL_quic_write_level returns the current write encryption level.
         */
    SSL_quic_write_level :: proc(ssl: SSL) -> ssl_encryption_level_t ---

        /*
         * SSL_provide_quic_data provides data from QUIC at a particular encryption
         * level |level|. It returns one on success and zero on error. Note this
         * function will return zero if the handshake is not expecting data from |level|
         * at this time. The QUIC implementation should then close the connection with
         * an error.
         */
    SSL_provide_quic_data :: proc(ssl: SSL,
				  level: ssl_encryption_level_t,
				  data: [^]c.uint8_t,
				  len: c.size_t) -> c.int ---

         /*
          * SSL_process_quic_post_handshake processes any data that QUIC has provided
          * after the handshake has completed. This includes NewSessionTicket messages
          * sent by the server. It returns one on success and zero on error.
          */
    SSL_process_quic_post_handshake :: proc(ssl: SSL) -> c.int ---

        /*
         * SSL_set_quic_transport_params configures |ssl| to send |params| (of length
         * |params_len|) in the quic_transport_parameters extension in either the
         * ClientHello or EncryptedExtensions handshake message. It is an error to set
         * transport parameters if |ssl| is not configured for QUIC. The buffer pointed
         * to by |params| only need be valid for the duration of the call to this
         * function. This function returns 1 on success and 0 on failure.
         */
    SSL_set_quic_transport_params :: proc(ssl: SSL,
					  params: [^]c.uint8_t,
					  params_len: c.size_t) -> c.int  ---

        /*
         * SSL_get_peer_quic_transport_params provides the caller with the value of the
         * quic_transport_parameters extension sent by the peer. A pointer to the buffer
         * containing the TransportParameters will be put in |*out_params|, and its
         * length in |*params_len|. This buffer will be valid for the lifetime of the
         * |SSL|. If no params were received from the peer, |*out_params_len| will be 0.
         */
    SSL_get_peer_quic_transport_params :: proc(ssl: SSL,
					       out_params: ^[^]c.uint8_t,
					       out_params_len: ^c.size_t) ---

	/*
         * SSL_set_quic_use_legacy_codepoint configures whether to use the legacy QUIC
         * extension codepoint 0xffa5 as opposed to the official value 57. This is
         * unsupported in LibreSSL.
         */
    SSL_set_quic_use_legacy_codepoint :: proc(ssl: SSL, use_legacy: c.int) ---

    ERR_load_SSL_strings :: proc() ---
}


/* Error codes for the SSL functions. */

/* Function codes. */
SSL_F_CLIENT_CERTIFICATE :: 100
SSL_F_CLIENT_FINISHED :: 167
SSL_F_CLIENT_HELLO :: 101
SSL_F_CLIENT_MASTER_KEY :: 102
SSL_F_D2I_SSL_SESSION :: 103
SSL_F_DO_DTLS1_WRITE :: 245
SSL_F_DO_SSL3_WRITE :: 104
SSL_F_DTLS1_ACCEPT :: 246
SSL_F_DTLS1_ADD_CERT_TO_BUF :: 295
SSL_F_DTLS1_BUFFER_RECORD :: 247
SSL_F_DTLS1_CHECK_TIMEOUT_NUM :: 316
SSL_F_DTLS1_CLIENT_HELLO :: 248
SSL_F_DTLS1_CONNECT :: 249
SSL_F_DTLS1_ENC :: 250
SSL_F_DTLS1_GET_HELLO_VERIFY :: 251
SSL_F_DTLS1_GET_MESSAGE :: 252
SSL_F_DTLS1_GET_MESSAGE_FRAGMENT :: 253
SSL_F_DTLS1_GET_RECORD :: 254
SSL_F_DTLS1_HANDLE_TIMEOUT :: 297
SSL_F_DTLS1_HEARTBEAT :: 305
SSL_F_DTLS1_OUTPUT_CERT_CHAIN :: 255
SSL_F_DTLS1_PREPROCESS_FRAGMENT :: 288
SSL_F_DTLS1_PROCESS_OUT_OF_SEQ_MESSAGE :: 256
SSL_F_DTLS1_PROCESS_RECORD :: 257
SSL_F_DTLS1_READ_BYTES :: 258
SSL_F_DTLS1_READ_FAILED :: 259
SSL_F_DTLS1_SEND_CERTIFICATE_REQUEST :: 260
SSL_F_DTLS1_SEND_CLIENT_CERTIFICATE :: 261
SSL_F_DTLS1_SEND_CLIENT_KEY_EXCHANGE :: 262
SSL_F_DTLS1_SEND_CLIENT_VERIFY :: 263
SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST :: 264
SSL_F_DTLS1_SEND_SERVER_CERTIFICATE :: 265
SSL_F_DTLS1_SEND_SERVER_HELLO :: 266
SSL_F_DTLS1_SEND_SERVER_KEY_EXCHANGE :: 267
SSL_F_DTLS1_WRITE_APP_DATA_BYTES :: 268
SSL_F_GET_CLIENT_FINISHED :: 105
SSL_F_GET_CLIENT_HELLO :: 106
SSL_F_GET_CLIENT_MASTER_KEY :: 107
SSL_F_GET_SERVER_FINISHED :: 108
SSL_F_GET_SERVER_HELLO :: 109
SSL_F_GET_SERVER_VERIFY :: 110
SSL_F_I2D_SSL_SESSION :: 111
SSL_F_READ_N :: 112
SSL_F_REQUEST_CERTIFICATE :: 113
SSL_F_SERVER_FINISH :: 239
SSL_F_SERVER_HELLO :: 114
SSL_F_SERVER_VERIFY :: 240
SSL_F_SSL23_ACCEPT :: 115
SSL_F_SSL23_CLIENT_HELLO :: 116
SSL_F_SSL23_CONNECT :: 117
SSL_F_SSL23_GET_CLIENT_HELLO :: 118
SSL_F_SSL23_GET_SERVER_HELLO :: 119
SSL_F_SSL23_PEEK :: 237
SSL_F_SSL23_READ :: 120
SSL_F_SSL23_WRITE :: 121
SSL_F_SSL2_ACCEPT :: 122
SSL_F_SSL2_CONNECT :: 123
SSL_F_SSL2_ENC_INIT :: 124
SSL_F_SSL2_GENERATE_KEY_MATERIAL :: 241
SSL_F_SSL2_PEEK :: 234
SSL_F_SSL2_READ :: 125
SSL_F_SSL2_READ_INTERNAL :: 236
SSL_F_SSL2_SET_CERTIFICATE :: 126
SSL_F_SSL2_WRITE :: 127
SSL_F_SSL3_ACCEPT :: 128
SSL_F_SSL3_ADD_CERT_TO_BUF :: 296
SSL_F_SSL3_CALLBACK_CTRL :: 233
SSL_F_SSL3_CHANGE_CIPHER_STATE :: 129
SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM :: 130
SSL_F_SSL3_CHECK_CLIENT_HELLO :: 304
SSL_F_SSL3_CLIENT_HELLO :: 131
SSL_F_SSL3_CONNECT :: 132
SSL_F_SSL3_CTRL :: 213
SSL_F_SSL3_CTX_CTRL :: 133
SSL_F_SSL3_DIGEST_CACHED_RECORDS :: 293
SSL_F_SSL3_DO_CHANGE_CIPHER_SPEC :: 292
SSL_F_SSL3_ENC :: 134
SSL_F_SSL3_GENERATE_KEY_BLOCK :: 238
SSL_F_SSL3_GET_CERTIFICATE_REQUEST :: 135
SSL_F_SSL3_GET_CERT_STATUS :: 289
SSL_F_SSL3_GET_CERT_VERIFY :: 136
SSL_F_SSL3_GET_CLIENT_CERTIFICATE :: 137
SSL_F_SSL3_GET_CLIENT_HELLO :: 138
SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE :: 139
SSL_F_SSL3_GET_FINISHED :: 140
SSL_F_SSL3_GET_KEY_EXCHANGE :: 141
SSL_F_SSL3_GET_MESSAGE :: 142
SSL_F_SSL3_GET_NEW_SESSION_TICKET :: 283
SSL_F_SSL3_GET_NEXT_PROTO :: 306
SSL_F_SSL3_GET_RECORD :: 143
SSL_F_SSL3_GET_SERVER_CERTIFICATE :: 144
SSL_F_SSL3_GET_SERVER_DONE :: 145
SSL_F_SSL3_GET_SERVER_HELLO :: 146
SSL_F_SSL3_HANDSHAKE_MAC :: 285
SSL_F_SSL3_NEW_SESSION_TICKET :: 287
SSL_F_SSL3_OUTPUT_CERT_CHAIN :: 147
SSL_F_SSL3_PEEK :: 235
SSL_F_SSL3_READ_BYTES :: 148
SSL_F_SSL3_READ_N :: 149
SSL_F_SSL3_SEND_CERTIFICATE_REQUEST :: 150
SSL_F_SSL3_SEND_CLIENT_CERTIFICATE :: 151
SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE :: 152
SSL_F_SSL3_SEND_CLIENT_VERIFY :: 153
SSL_F_SSL3_SEND_SERVER_CERTIFICATE :: 154
SSL_F_SSL3_SEND_SERVER_HELLO :: 242
SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE :: 155
SSL_F_SSL3_SETUP_KEY_BLOCK :: 157
SSL_F_SSL3_SETUP_READ_BUFFER :: 156
SSL_F_SSL3_SETUP_WRITE_BUFFER :: 291
SSL_F_SSL3_WRITE_BYTES :: 158
SSL_F_SSL3_WRITE_PENDING :: 159
SSL_F_SSL_ADD_CLIENTHELLO_RENEGOTIATE_EXT :: 298
SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT :: 277
SSL_F_SSL_ADD_CLIENTHELLO_USE_SRTP_EXT :: 307
SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK :: 215
SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK :: 216
SSL_F_SSL_ADD_SERVERHELLO_RENEGOTIATE_EXT :: 299
SSL_F_SSL_ADD_SERVERHELLO_TLSEXT :: 278
SSL_F_SSL_ADD_SERVERHELLO_USE_SRTP_EXT :: 308
SSL_F_SSL_BAD_METHOD :: 160
SSL_F_SSL_BYTES_TO_CIPHER_LIST :: 161
SSL_F_SSL_CERT_DUP :: 221
SSL_F_SSL_CERT_INST :: 222
SSL_F_SSL_CERT_INSTANTIATE :: 214
SSL_F_SSL_CERT_NEW :: 162
SSL_F_SSL_CHECK_PRIVATE_KEY :: 163
SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT :: 280
SSL_F_SSL_CHECK_SRVR_ECC_CERT_AND_ALG :: 279
SSL_F_SSL_CIPHER_PROCESS_RULESTR :: 230
SSL_F_SSL_CIPHER_STRENGTH_SORT :: 231
SSL_F_SSL_CLEAR :: 164
SSL_F_SSL_COMP_ADD_COMPRESSION_METHOD :: 165
SSL_F_SSL_CREATE_CIPHER_LIST :: 166
SSL_F_SSL_CTRL :: 232
SSL_F_SSL_CTX_CHECK_PRIVATE_KEY :: 168
SSL_F_SSL_CTX_MAKE_PROFILES :: 309
SSL_F_SSL_CTX_NEW :: 169
SSL_F_SSL_CTX_SET_CIPHER_LIST :: 269
SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE :: 290
SSL_F_SSL_CTX_SET_PURPOSE :: 226
SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT :: 219
SSL_F_SSL_CTX_SET_SSL_VERSION :: 170
SSL_F_SSL_CTX_SET_TRUST :: 229
SSL_F_SSL_CTX_USE_CERTIFICATE :: 171
SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1 :: 172
SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE :: 220
SSL_F_SSL_CTX_USE_CERTIFICATE_FILE :: 173
SSL_F_SSL_CTX_USE_PRIVATEKEY :: 174
SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1 :: 175
SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE :: 176
SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT :: 272
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY :: 177
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1 :: 178
SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE :: 179
SSL_F_SSL_DO_HANDSHAKE :: 180
SSL_F_SSL_GET_NEW_SESSION :: 181
SSL_F_SSL_GET_PREV_SESSION :: 217
SSL_F_SSL_GET_SERVER_SEND_CERT :: 182
SSL_F_SSL_GET_SERVER_SEND_PKEY :: 317
SSL_F_SSL_GET_SIGN_PKEY :: 183
SSL_F_SSL_INIT_WBIO_BUFFER :: 184
SSL_F_SSL_LOAD_CLIENT_CA_FILE :: 185
SSL_F_SSL_NEW :: 186
SSL_F_SSL_PARSE_CLIENTHELLO_RENEGOTIATE_EXT :: 300
SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT :: 302
SSL_F_SSL_PARSE_CLIENTHELLO_USE_SRTP_EXT :: 310
SSL_F_SSL_PARSE_SERVERHELLO_RENEGOTIATE_EXT :: 301
SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT :: 303
SSL_F_SSL_PARSE_SERVERHELLO_USE_SRTP_EXT :: 311
SSL_F_SSL_PEEK :: 270
SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT :: 281
SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT :: 282
SSL_F_SSL_READ :: 223
SSL_F_SSL_RSA_PRIVATE_DECRYPT :: 187
SSL_F_SSL_RSA_PUBLIC_ENCRYPT :: 188
SSL_F_SSL_SESSION_NEW :: 189
SSL_F_SSL_SESSION_PRINT_FP :: 190
SSL_F_SSL_SESSION_SET1_ID_CONTEXT :: 312
SSL_F_SSL_SESS_CERT_NEW :: 225
SSL_F_SSL_SET_CERT :: 191
SSL_F_SSL_SET_CIPHER_LIST :: 271
SSL_F_SSL_SET_FD :: 192
SSL_F_SSL_SET_PKEY :: 193
SSL_F_SSL_SET_PURPOSE :: 227
SSL_F_SSL_SET_RFD :: 194
SSL_F_SSL_SET_SESSION :: 195
SSL_F_SSL_SET_SESSION_ID_CONTEXT :: 218
SSL_F_SSL_SET_SESSION_TICKET_EXT :: 294
SSL_F_SSL_SET_TRUST :: 228
SSL_F_SSL_SET_WFD :: 196
SSL_F_SSL_SHUTDOWN :: 224
SSL_F_SSL_SRP_CTX_INIT :: 313
SSL_F_SSL_UNDEFINED__FUNCTION :: 243
SSL_F_SSL_UNDEFINED_FUNCTION :: 197
SSL_F_SSL_UNDEFINED_VOID_FUNCTION :: 244
SSL_F_SSL_USE_CERTIFICATE :: 198
SSL_F_SSL_USE_CERTIFICATE_ASN1 :: 199
SSL_F_SSL_USE_CERTIFICATE_FILE :: 200
SSL_F_SSL_USE_PRIVATEKEY :: 201
SSL_F_SSL_USE_PRIVATEKEY_ASN1 :: 202
SSL_F_SSL_USE_PRIVATEKEY_FILE :: 203
SSL_F_SSL_USE_PSK_IDENTITY_HINT :: 273
SSL_F_SSL_USE_RSAPRIVATEKEY :: 204
SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1 :: 205
SSL_F_SSL_USE_RSAPRIVATEKEY_FILE :: 206
SSL_F_SSL_VERIFY_CERT_CHAIN :: 207
SSL_F_SSL_WRITE :: 208
SSL_F_TLS1_AEAD_CTX_INIT :: 339
SSL_F_TLS1_CERT_VERIFY_MAC :: 286
SSL_F_TLS1_CHANGE_CIPHER_STATE :: 209
SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD :: 340
SSL_F_TLS1_CHANGE_CIPHER_STATE_CIPHER :: 338
SSL_F_TLS1_CHECK_SERVERHELLO_TLSEXT :: 274
SSL_F_TLS1_ENC :: 210
SSL_F_TLS1_EXPORT_KEYING_MATERIAL :: 314
SSL_F_TLS1_HEARTBEAT :: 315
SSL_F_TLS1_PREPARE_CLIENTHELLO_TLSEXT :: 275
SSL_F_TLS1_PREPARE_SERVERHELLO_TLSEXT :: 276
SSL_F_TLS1_PRF :: 284
SSL_F_TLS1_SETUP_KEY_BLOCK :: 211
SSL_F_WRITE_PENDING :: 212

/* Reason codes. */
SSL_R_APP_DATA_IN_HANDSHAKE :: 100
SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT :: 272
SSL_R_BAD_ALERT_RECORD :: 101
SSL_R_BAD_AUTHENTICATION_TYPE :: 102
SSL_R_BAD_CHANGE_CIPHER_SPEC :: 103
SSL_R_BAD_CHECKSUM :: 104
SSL_R_BAD_DATA_RETURNED_BY_CALLBACK :: 106
SSL_R_BAD_DECOMPRESSION :: 107
SSL_R_BAD_DH_G_LENGTH :: 108
SSL_R_BAD_DH_PUB_KEY_LENGTH :: 109
SSL_R_BAD_DH_P_LENGTH :: 110
SSL_R_BAD_DIGEST_LENGTH :: 111
SSL_R_BAD_DSA_SIGNATURE :: 112
SSL_R_BAD_ECC_CERT :: 304
SSL_R_BAD_ECDSA_SIGNATURE :: 305
SSL_R_BAD_ECPOINT :: 306
SSL_R_BAD_HANDSHAKE_LENGTH :: 332
SSL_R_BAD_HELLO_REQUEST :: 105
SSL_R_BAD_LENGTH :: 271
SSL_R_BAD_MAC_DECODE :: 113
SSL_R_BAD_MAC_LENGTH :: 333
SSL_R_BAD_MESSAGE_TYPE :: 114
SSL_R_BAD_PACKET_LENGTH :: 115
SSL_R_BAD_PROTOCOL_VERSION_NUMBER :: 116
SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH :: 316
SSL_R_BAD_RESPONSE_ARGUMENT :: 117
SSL_R_BAD_RSA_DECRYPT :: 118
SSL_R_BAD_RSA_ENCRYPT :: 119
SSL_R_BAD_RSA_E_LENGTH :: 120
SSL_R_BAD_RSA_MODULUS_LENGTH :: 121
SSL_R_BAD_RSA_SIGNATURE :: 122
SSL_R_BAD_SIGNATURE :: 123
SSL_R_BAD_SRP_A_LENGTH :: 347
SSL_R_BAD_SRP_B_LENGTH :: 348
SSL_R_BAD_SRP_G_LENGTH :: 349
SSL_R_BAD_SRP_N_LENGTH :: 350
SSL_R_BAD_SRP_S_LENGTH :: 351
SSL_R_BAD_SRTP_MKI_VALUE :: 352
SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST :: 353
SSL_R_BAD_SSL_FILETYPE :: 124
SSL_R_BAD_SSL_SESSION_ID_LENGTH :: 125
SSL_R_BAD_STATE :: 126
SSL_R_BAD_WRITE_RETRY :: 127
SSL_R_BIO_NOT_SET :: 128
SSL_R_BLOCK_CIPHER_PAD_IS_WRONG :: 129
SSL_R_BN_LIB :: 130
SSL_R_CA_DN_LENGTH_MISMATCH :: 131
SSL_R_CA_DN_TOO_LONG :: 132
SSL_R_CA_KEY_TOO_SMALL :: 397
SSL_R_CA_MD_TOO_WEAK :: 398
SSL_R_CCS_RECEIVED_EARLY :: 133
SSL_R_CERTIFICATE_VERIFY_FAILED :: 134
SSL_R_CERT_LENGTH_MISMATCH :: 135
SSL_R_CHALLENGE_IS_DIFFERENT :: 136
SSL_R_CIPHER_CODE_WRONG_LENGTH :: 137
SSL_R_CIPHER_COMPRESSION_UNAVAILABLE :: 371
SSL_R_CIPHER_OR_HASH_UNAVAILABLE :: 138
SSL_R_CIPHER_TABLE_SRC_ERROR :: 139
SSL_R_CLIENTHELLO_TLSEXT :: 226
SSL_R_COMPRESSED_LENGTH_TOO_LONG :: 140
SSL_R_COMPRESSION_DISABLED :: 343
SSL_R_COMPRESSION_FAILURE :: 141
SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE :: 307
SSL_R_COMPRESSION_LIBRARY_ERROR :: 142
SSL_R_CONNECTION_ID_IS_DIFFERENT :: 143
SSL_R_CONNECTION_TYPE_NOT_SET :: 144
SSL_R_COOKIE_MISMATCH :: 308
SSL_R_DATA_BETWEEN_CCS_AND_FINISHED :: 145
SSL_R_DATA_LENGTH_TOO_LONG :: 146
SSL_R_DECRYPTION_FAILED :: 147
SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC :: 281
SSL_R_DH_KEY_TOO_SMALL :: 394
SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG :: 148
SSL_R_DIGEST_CHECK_FAILED :: 149
SSL_R_DTLS_MESSAGE_TOO_BIG :: 334
SSL_R_DUPLICATE_COMPRESSION_ID :: 309
SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT :: 317
SSL_R_ECC_CERT_NOT_FOR_SIGNING :: 318
SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE :: 322
SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE :: 323
SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER :: 310
SSL_R_EE_KEY_TOO_SMALL :: 399
SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST :: 354
SSL_R_ENCRYPTED_LENGTH_TOO_LONG :: 150
SSL_R_ERROR_GENERATING_TMP_RSA_KEY :: 282
SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST :: 151
SSL_R_EXCESSIVE_MESSAGE_SIZE :: 152
SSL_R_EXTRA_DATA_IN_MESSAGE :: 153
SSL_R_GOT_A_FIN_BEFORE_A_CCS :: 154
SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS :: 355
SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION :: 356
SSL_R_HTTPS_PROXY_REQUEST :: 155
SSL_R_HTTP_REQUEST :: 156
SSL_R_ILLEGAL_PADDING :: 283
SSL_R_INAPPROPRIATE_FALLBACK :: 373
SSL_R_INCONSISTENT_COMPRESSION :: 340
SSL_R_INVALID_CHALLENGE_LENGTH :: 158
SSL_R_INVALID_COMMAND :: 280
SSL_R_INVALID_COMPRESSION_ALGORITHM :: 341
SSL_R_INVALID_PURPOSE :: 278
SSL_R_INVALID_SRP_USERNAME :: 357
SSL_R_INVALID_STATUS_RESPONSE :: 328
SSL_R_INVALID_TICKET_KEYS_LENGTH :: 325
SSL_R_INVALID_TRUST :: 279
SSL_R_KEY_ARG_TOO_LONG :: 284
SSL_R_KRB5 :: 285
SSL_R_KRB5_C_CC_PRINC :: 286
SSL_R_KRB5_C_GET_CRED :: 287
SSL_R_KRB5_C_INIT :: 288
SSL_R_KRB5_C_MK_REQ :: 289
SSL_R_KRB5_S_BAD_TICKET :: 290
SSL_R_KRB5_S_INIT :: 291
SSL_R_KRB5_S_RD_REQ :: 292
SSL_R_KRB5_S_TKT_EXPIRED :: 293
SSL_R_KRB5_S_TKT_NYV :: 294
SSL_R_KRB5_S_TKT_SKEW :: 295
SSL_R_LENGTH_MISMATCH :: 159
SSL_R_LENGTH_TOO_SHORT :: 160
SSL_R_LIBRARY_BUG :: 274
SSL_R_LIBRARY_HAS_NO_CIPHERS :: 161
SSL_R_MESSAGE_TOO_LONG :: 296
SSL_R_MISSING_DH_DSA_CERT :: 162
SSL_R_MISSING_DH_KEY :: 163
SSL_R_MISSING_DH_RSA_CERT :: 164
SSL_R_MISSING_DSA_SIGNING_CERT :: 165
SSL_R_MISSING_EXPORT_TMP_DH_KEY :: 166
SSL_R_MISSING_EXPORT_TMP_RSA_KEY :: 167
SSL_R_MISSING_RSA_CERTIFICATE :: 168
SSL_R_MISSING_RSA_ENCRYPTING_CERT :: 169
SSL_R_MISSING_RSA_SIGNING_CERT :: 170
SSL_R_MISSING_SRP_PARAM :: 358
SSL_R_MISSING_TMP_DH_KEY :: 171
SSL_R_MISSING_TMP_ECDH_KEY :: 311
SSL_R_MISSING_TMP_RSA_KEY :: 172
SSL_R_MISSING_TMP_RSA_PKEY :: 173
SSL_R_MISSING_VERIFY_MESSAGE :: 174
SSL_R_MULTIPLE_SGC_RESTARTS :: 346
SSL_R_NON_SSLV2_INITIAL_PACKET :: 175
SSL_R_NO_APPLICATION_PROTOCOL :: 235
SSL_R_NO_CERTIFICATES_RETURNED :: 176
SSL_R_NO_CERTIFICATE_ASSIGNED :: 177
SSL_R_NO_CERTIFICATE_RETURNED :: 178
SSL_R_NO_CERTIFICATE_SET :: 179
SSL_R_NO_CERTIFICATE_SPECIFIED :: 180
SSL_R_NO_CIPHERS_AVAILABLE :: 181
SSL_R_NO_CIPHERS_PASSED :: 182
SSL_R_NO_CIPHERS_SPECIFIED :: 183
SSL_R_NO_CIPHER_LIST :: 184
SSL_R_NO_CIPHER_MATCH :: 185
SSL_R_NO_CLIENT_CERT_METHOD :: 331
SSL_R_NO_CLIENT_CERT_RECEIVED :: 186
SSL_R_NO_COMPRESSION_SPECIFIED :: 187
SSL_R_NO_METHOD_SPECIFIED :: 188
SSL_R_NO_PRIVATEKEY :: 189
SSL_R_NO_PRIVATE_KEY_ASSIGNED :: 190
SSL_R_NO_PROTOCOLS_AVAILABLE :: 191
SSL_R_NO_PUBLICKEY :: 192
SSL_R_NO_RENEGOTIATION :: 339
SSL_R_NO_REQUIRED_DIGEST :: 324
SSL_R_NO_SHARED_CIPHER :: 193
SSL_R_NO_SRTP_PROFILES :: 359
SSL_R_NO_VERIFY_CALLBACK :: 194
SSL_R_NULL_SSL_CTX :: 195
SSL_R_NULL_SSL_METHOD_PASSED :: 196
SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED :: 197
SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED :: 344
SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE :: 297
SSL_R_PACKET_LENGTH_TOO_LONG :: 198
SSL_R_PARSE_TLSEXT :: 227
SSL_R_PATH_TOO_LONG :: 270
SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE :: 199
SSL_R_PEER_ERROR :: 200
SSL_R_PEER_ERROR_CERTIFICATE :: 201
SSL_R_PEER_ERROR_NO_CERTIFICATE :: 202
SSL_R_PEER_ERROR_NO_CIPHER :: 203
SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE :: 204
SSL_R_PRE_MAC_LENGTH_TOO_LONG :: 205
SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS :: 206
SSL_R_PROTOCOL_IS_SHUTDOWN :: 207
SSL_R_PSK_IDENTITY_NOT_FOUND :: 223
SSL_R_PSK_NO_CLIENT_CB :: 224
SSL_R_PSK_NO_SERVER_CB :: 225
SSL_R_PUBLIC_KEY_ENCRYPT_ERROR :: 208
SSL_R_PUBLIC_KEY_IS_NOT_RSA :: 209
SSL_R_PUBLIC_KEY_NOT_RSA :: 210
SSL_R_READ_BIO_NOT_SET :: 211
SSL_R_READ_TIMEOUT_EXPIRED :: 312
SSL_R_READ_WRONG_PACKET_TYPE :: 212
SSL_R_RECORD_LENGTH_MISMATCH :: 213
SSL_R_RECORD_TOO_LARGE :: 214
SSL_R_RECORD_TOO_SMALL :: 298
SSL_R_RENEGOTIATE_EXT_TOO_LONG :: 335
SSL_R_RENEGOTIATION_ENCODING_ERR :: 336
SSL_R_RENEGOTIATION_MISMATCH :: 337
SSL_R_REQUIRED_CIPHER_MISSING :: 215
SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING :: 342
SSL_R_REUSE_CERT_LENGTH_NOT_ZERO :: 216
SSL_R_REUSE_CERT_TYPE_NOT_ZERO :: 217
SSL_R_REUSE_CIPHER_LIST_NOT_ZERO :: 218
SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING :: 345
SSL_R_SERVERHELLO_TLSEXT :: 275
SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED :: 277
SSL_R_SHORT_READ :: 219
SSL_R_SIGNATURE_ALGORITHMS_ERROR :: 360
SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE :: 220
SSL_R_SRP_A_CALC :: 361
SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES :: 362
SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG :: 363
SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE :: 364
SSL_R_SSL23_DOING_SESSION_ID_REUSE :: 221
SSL_R_SSL2_CONNECTION_ID_TOO_LONG :: 299
SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT :: 321
SSL_R_SSL3_EXT_INVALID_SERVERNAME :: 319
SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE :: 320
SSL_R_SSL3_SESSION_ID_TOO_LONG :: 300
SSL_R_SSL3_SESSION_ID_TOO_SHORT :: 222
SSL_R_SSLV3_ALERT_BAD_CERTIFICATE :: 1042
SSL_R_SSLV3_ALERT_BAD_RECORD_MAC :: 1020
SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED :: 1045
SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED :: 1044
SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN :: 1046
SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE :: 1030
SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE :: 1040
SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER :: 1047
SSL_R_SSLV3_ALERT_NO_CERTIFICATE :: 1041
SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE :: 1010
SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE :: 1043
SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION :: 228
SSL_R_SSL_HANDSHAKE_FAILURE :: 229
SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS :: 230
SSL_R_SSL_SESSION_ID_CALLBACK_FAILED :: 301
SSL_R_SSL_SESSION_ID_CONFLICT :: 302
SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG :: 273
SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH :: 303
SSL_R_SSL_SESSION_ID_IS_DIFFERENT :: 231
SSL_R_SSL_SESSION_ID_TOO_LONG :: 408
SSL_R_TLSV1_ALERT_ACCESS_DENIED :: 1049
SSL_R_TLSV1_ALERT_DECODE_ERROR :: 1050
SSL_R_TLSV1_ALERT_DECRYPTION_FAILED :: 1021
SSL_R_TLSV1_ALERT_DECRYPT_ERROR :: 1051
SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION :: 1060
SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK :: 1086
SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY :: 1071
SSL_R_TLSV1_ALERT_INTERNAL_ERROR :: 1080
SSL_R_TLSV1_ALERT_NO_RENEGOTIATION :: 1100
SSL_R_TLSV1_ALERT_PROTOCOL_VERSION :: 1070
SSL_R_TLSV1_ALERT_RECORD_OVERFLOW :: 1022
SSL_R_TLSV1_ALERT_UNKNOWN_CA :: 1048
SSL_R_TLSV1_ALERT_USER_CANCELLED :: 1090
SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE :: 1114
SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE :: 1113
SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE :: 1111
SSL_R_TLSV1_UNRECOGNIZED_NAME :: 1112
SSL_R_TLSV1_UNSUPPORTED_EXTENSION :: 1110
SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER :: 232
SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT :: 365
SSL_R_TLS_HEARTBEAT_PENDING :: 366
SSL_R_TLS_ILLEGAL_EXPORTER_LABEL :: 367
SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST :: 157
SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST :: 233
SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG :: 234
SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER :: 235
SSL_R_UNABLE_TO_DECODE_DH_CERTS :: 236
SSL_R_UNABLE_TO_DECODE_ECDH_CERTS :: 313
SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY :: 237
SSL_R_UNABLE_TO_FIND_DH_PARAMETERS :: 238
SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS :: 314
SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS :: 239
SSL_R_UNABLE_TO_FIND_SSL_METHOD :: 240
SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES :: 241
SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES :: 242
SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES :: 243
SSL_R_UNEXPECTED_MESSAGE :: 244
SSL_R_UNEXPECTED_RECORD :: 245
SSL_R_UNINITIALIZED :: 276
SSL_R_UNKNOWN_ALERT_TYPE :: 246
SSL_R_UNKNOWN_CERTIFICATE_TYPE :: 247
SSL_R_UNKNOWN_CIPHER_RETURNED :: 248
SSL_R_UNKNOWN_CIPHER_TYPE :: 249
SSL_R_UNKNOWN_DIGEST :: 368
SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE :: 250
SSL_R_UNKNOWN_PKEY_TYPE :: 251
SSL_R_UNKNOWN_PROTOCOL :: 252
SSL_R_UNKNOWN_REMOTE_ERROR_TYPE :: 253
SSL_R_UNKNOWN_SSL_VERSION :: 254
SSL_R_UNKNOWN_STATE :: 255
SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED :: 338
SSL_R_UNSUPPORTED_CIPHER :: 256
SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM :: 257
SSL_R_UNSUPPORTED_DIGEST_TYPE :: 326
SSL_R_UNSUPPORTED_ELLIPTIC_CURVE :: 315
SSL_R_UNSUPPORTED_PROTOCOL :: 258
SSL_R_UNSUPPORTED_SSL_VERSION :: 259
SSL_R_UNSUPPORTED_STATUS_TYPE :: 329
SSL_R_USE_SRTP_NOT_NEGOTIATED :: 369
SSL_R_VERSION_TOO_LOW :: 396
SSL_R_WRITE_BIO_NOT_SET :: 260
SSL_R_WRONG_CIPHER_RETURNED :: 261
SSL_R_WRONG_CURVE :: 378
SSL_R_WRONG_MESSAGE_TYPE :: 262
SSL_R_WRONG_NUMBER_OF_KEY_BITS :: 263
SSL_R_WRONG_SIGNATURE_LENGTH :: 264
SSL_R_WRONG_SIGNATURE_SIZE :: 265
SSL_R_WRONG_SIGNATURE_TYPE :: 370
SSL_R_WRONG_SSL_VERSION :: 266
SSL_R_WRONG_VERSION_NUMBER :: 267
SSL_R_X509_LIB :: 268
SSL_R_X509_VERIFICATION_SETUP_PROBLEMS :: 269
SSL_R_PEER_BEHAVING_BADLY :: 666
SSL_R_QUIC_INTERNAL_ERROR :: 667
SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED :: 668
SSL_R_UNKNOWN :: 999

/*
 * OpenSSL compatible OPENSSL_INIT options
 */

/*
 * These are provided for compatibility, but have no effect
 * on how LibreSSL is initialized.
 */
/*
    // Since these are for compatibility with older c libraries
    // they're probably unnecessary in our Odin bindings

    OPENSSL_INIT_LOAD_SSL_STRINGS :: _OPENSSL_INIT_FLAG_NOOP
    OPENSSL_INIT_SSL_DEFAULT :: _OPENSSL_INIT_FLAG_NOOP
    
    OPENSSL_init_ssl(uint64_t opts,  void *settings) -> c.int
    int SSL_library_init(void);
*/
/*
 * A few things still use this without #ifdef guard.
 */

SSL2_VERSION :: 0x0002
