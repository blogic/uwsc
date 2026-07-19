/*
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "client-internal.h"
#include "ssl.h"
#include "log.h"

/* Get detailed SSL error string */
static const char *
uwsc_ssl_get_error_string(SSL *ssl, int ret)
{
	static char error_buf[256];
	int err = SSL_get_error(ssl, ret);
	unsigned long openssl_err;

	switch (err) {
	case SSL_ERROR_NONE:
		return "No error";
	case SSL_ERROR_SSL:
		openssl_err = ERR_get_error();
		if (openssl_err) {
			ERR_error_string_n(openssl_err, error_buf, sizeof(error_buf));
			return error_buf;
		}
		return "SSL protocol error";
	case SSL_ERROR_WANT_READ:
		return "Want read";
	case SSL_ERROR_WANT_WRITE:
		return "Want write";
	case SSL_ERROR_SYSCALL:
		openssl_err = ERR_get_error();
		if (openssl_err) {
			ERR_error_string_n(openssl_err, error_buf, sizeof(error_buf));
			return error_buf;
		}
		if (ret == 0)
			return "Connection closed";
		snprintf(error_buf, sizeof(error_buf), "System error: %s", strerror(errno));
		return error_buf;
	case SSL_ERROR_ZERO_RETURN:
		return "SSL connection closed";
	case SSL_ERROR_WANT_CONNECT:
		return "Want connect";
	case SSL_ERROR_WANT_ACCEPT:
		return "Want accept";
	default:
		snprintf(error_buf, sizeof(error_buf), "Unknown SSL error %d", err);
		return error_buf;
	}
}

/* Get X509 verification error string */
static const char *
uwsc_ssl_get_verify_error_string(long verify_result)
{
	return X509_verify_cert_error_string(verify_result);
}

__hidden bool
uwsc_ssl_init_client_ctx(void)
{
	/* No longer using a global context - each client gets its own */
	return true;
}

__hidden void *
uwsc_ssl_create_client(uwsc_client_t *client)
{
	SSL_CTX *ssl_ctx;
	SSL *ssl;

	if (!client || client->conn.ufd.fd < 0)
		return NULL;

	/* Create a new SSL context for this client */
	ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!ssl_ctx) {
		uwsc_log_err(NULL, "Failed to create SSL context");
		return NULL;
	}

	/* Set default certificate paths */
	SSL_CTX_set_default_verify_paths(ssl_ctx);

	/* Set SSL mode for non-blocking I/O */
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

	/* Load custom CA certificate if provided */
	if (client->ca_cert_path) {
		if (!SSL_CTX_load_verify_locations(ssl_ctx, client->ca_cert_path, NULL)) {
			unsigned long err = ERR_get_error();
			char err_buf[256];
			ERR_error_string_n(err, err_buf, sizeof(err_buf));
			uwsc_log_err(NULL, "Failed to load CA certificate from %s: %s", client->ca_cert_path, err_buf);
			SSL_CTX_free(ssl_ctx);
			return NULL;
		}
	}

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	if (SSL_set_fd(ssl, client->conn.ufd.fd) != 1) {
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	if (client->host && SSL_set_tlsext_host_name(ssl, client->host) != 1) {
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}

	/* Set verification mode based on configuration */
	if (client->ssl_verify) {
		SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
	} else {
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
	}

	return ssl;
}

__hidden int
uwsc_ssl_connect(struct uwsc_connection *conn)
{
	SSL *ssl = (SSL *)conn->ssl;
	int ret;

	if (!ssl)
		return -1;

	ret = SSL_connect(ssl);

	if (ret == 1)
		return 1; /* Success */

	int err = SSL_get_error(ssl, ret);

	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
		return 0; /* Would block */

	/* Log detailed SSL error */
	const char *error_str = uwsc_ssl_get_error_string(ssl, ret);
	uwsc_log_err(NULL, "SSL handshake failed: %s", error_str);

	return -1; /* Error */
}

__hidden bool
uwsc_ssl_verify_peer(uwsc_client_t *client)
{
	SSL *ssl;
	X509 *cert;
	long verify_result;

	if (!client || !client->conn.ssl)
		return false;

	ssl = (SSL *)client->conn.ssl;

	verify_result = SSL_get_verify_result(ssl);
	if (verify_result != X509_V_OK) {
		const char *verify_error = uwsc_ssl_get_verify_error_string(verify_result);
		uwsc_log_err(NULL, "Certificate verification failed: %s", verify_error);
		return false;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		uwsc_log_err(NULL, "No peer certificate presented");
		return false;
	}

	/* Verify hostname if provided */
	if (client->host) {
		int match = X509_check_host(cert, client->host, strlen(client->host), 0, NULL);
		X509_free(cert);
		return match == 1;
	}

	X509_free(cert);
	return true;
}

__hidden ssize_t
uwsc_ssl_pending(uwsc_connection_t *conn)
{
	SSL *ssl = conn->ssl;

	return SSL_pending(ssl);
}

__hidden ssize_t
uwsc_ssl_recv(uwsc_connection_t *conn, void *data, size_t len)
{
	SSL *ssl = conn->ssl;
	int err;

	errno = 0;
	err = SSL_read(ssl, data, len);

	switch (SSL_get_error(ssl, err)) {
	case SSL_ERROR_NONE:
		return err;

	case SSL_ERROR_ZERO_RETURN:
		return 0;

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return -1;

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		errno = EINPROGRESS;

		return -1;

	case SSL_ERROR_SYSCALL:
		if (errno == 0)
			errno = EPIPE;

		return -1;

	default:
		errno = EINVAL;

		return -1;
	}
}

__hidden ssize_t
uwsc_ssl_sendv(uwsc_connection_t *conn, struct iovec *iov, size_t len)
{
	SSL *ssl = conn->ssl;
	ssize_t total = 0;
	size_t i;
	int err;

	errno = 0;

	for (i = 0; i < len; i++) {
		if (iov[i].iov_len == 0)
			continue;

		err = SSL_write(ssl, iov[i].iov_base, iov[i].iov_len);

		switch (SSL_get_error(ssl, err)) {
		case SSL_ERROR_NONE:
			total += err;
			break;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			if (total)
				return total;

			errno = EAGAIN;

			return -1;

		case SSL_ERROR_SYSCALL:
			if (total)
				return total;

			return -1;

		default:
			if (total)
				return total;

			errno = EINVAL;

			return -1;
		}
	}

	return total;
}

__hidden ssize_t
uwsc_ssl_close(uwsc_connection_t *conn)
{
	SSL *ssl = conn->ssl;

	return SSL_shutdown(ssl);
}

__hidden void
uwsc_ssl_free(uwsc_connection_t *conn)
{
	SSL *ssl = conn->ssl;
	SSL_CTX *ctx;

	if (!ssl)
		return;

	/* Best-effort close_notify; the socket is nonblocking and may be dead */
	SSL_shutdown(ssl);

	/* Each client owns its context (see uwsc_ssl_create_client); SSL_free
	 * drops the SSL object's reference, SSL_CTX_free the creation one */
	ctx = SSL_get_SSL_CTX(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	conn->ssl = NULL;
}

bool
uwsc_client_ssl_init(uwsc_client_t *client)
{
	if (!client)
		return false;

	if (client->conn.ssl)
		return true;

	client->conn.ssl = uwsc_ssl_create_client(client);
	if (!client->conn.ssl) {
		uwsc_log_err(NULL, "Failed to create SSL client connection");
		return false;
	}

	return true;
}

bool
uwsc_client_ssl_connect(uwsc_client_t *client)
{
	int ret;

	if (!client || !client->conn.ssl)
		return false;

	ret = uwsc_ssl_connect(&client->conn);
	if (ret < 0) {
		uwsc_log_err(NULL, "SSL connect failed");
		return false;
	}
	else if (ret == 0) {
		uwsc_log_debug(NULL, "SSL connect would block, continuing asynchronously");
		return true;
	}

	/* Additional hostname verification if ssl_verify is enabled */
	/* Skip hostname verification when using custom CA (for self-signed certs) */
	if (client->ssl_verify && !client->ca_cert_path && !uwsc_ssl_verify_peer(client)) {
		uwsc_log_err(NULL, "SSL certificate hostname verification failed for %s", client->host);
		return false;
	}

	uwsc_log_debug(NULL, "SSL handshake completed successfully");
	return true;
}
