package ssl

import "core:net"
import libressl "./bindings"
import "core:c"

SSL_Context :: libressl.SSL_CTX
SSL_Connection :: libressl.SSL
QUIC_Encryption_Level :: libressl.ssl_encryption_level_t

SSL_Error :: enum {
    SSL_ERROR_NONE,
    SSL_ERROR_SSL,
    SSL_ERROR_WANT_READ,
    SSL_ERROR_WANT_WRITE,
    SSL_ERROR_WANT_X509_LOOKUP,
    SSL_ERROR_SYSCALL,
    SSL_ERROR_ZERO_RETURN,
    SSL_ERROR_WANT_CONNECT,
    SSL_ERROR_WANT_ACCEPT,
    SSL_ERROR_WANT_ASYNC,
    SSL_ERROR_WANT_ASYNC_JOB,
    SSL_ERROR_WANT_CLIENT_HELLO_CB,
}

Certificate :: enum {
    ASN1 = 2,
    PEM = 1,
}

create_ctx :: proc(certPath: string, pkeyPath: string, certType: Certificate, pkeyType: Certificate) -> SSL_Context {
    method := libressl.TLS_method()
    ctx := libressl.SSL_CTX_new(method)

    /* setting min protocol to TLSv1.3. FIXME: make this configurable */
    libressl.SSL_CTX_set_min_proto_version(ctx, libressl.SSL_OP_NO_TLSv1_3)

    /* setting up cryptography */
    libressl.SSL_CTX_use_certificate_file(certPath, certType)
    libressl.SSL_CTX_use_PrivateKey_file(pkeyPath, pkeyType)
    return ctx
}

create_conn :: proc(ctx: SSL_Context, port: net.TCP_Socket) -> SSL_Connection {
    conn := libressl.SSL_new(ctx)
    libressl.SSL_set_fd(int(port))
    return conn
}

accept :: proc(conn: SSL_Connection) -> SSL_Error {
    status :=  SSL_accept(conn)
    if status != 0 {
	return SSL_Error[int(status)]
    }
    return nil
}

// FIXME: We should really be using some sort of reader here
read_to_string :: proc(conn: SSL_Connection, bytes_wanted := 100) -> (string, SSL_Error) {
    buf := [bytes_wanted]u8{} // do we need to free this?
    bytes_read := -1
    status := SSL_read_ex(conn, &buf, bytes_wanted, &bytes_read)

    out : string

    for bytes_read !=0 {
	if status == 0 {
	    out += buf[:int(bytes_readi)]
	} else {
	    return "", SSL_Error[int(status)]
	}
    }
    return out
}

// FIXME: what if the buffer is YUGE?
// we should probably let the caller pass a writer or something
write_from_buffer :: proc(conn: SSL_Connection, response: []u8) -> SSL_Error {
    status := SSL_write_ex(conn, &response, len(response))
    if status != 0 {
	return SSL_ERROR[int(status)]
    }
    return nil
}

// are we allowed to just name it free?
// maybe if we import core:mem and use it's
// deallocator instead? It'd be awfully convenient
free_conn :: proc(conn: SSL_Connection) {
    SSL_free(conn)
}

create_quic_ctx :: proc() -> (SSL_Context, int) {
    method : libressl.SSL_QUIC_METHOD // FIXME: initialize

    err := libressl.SSL_CTX_set_quic_method(ctx, &method) or_return
     
}
