/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
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

#include <ucode/lib.h>
#include <libubox/uloop.h>

#include "client-internal.h"
#include "log.h"

#define REQUIRED	0
#define OPTIONAL	1
#define NAMED		2

static int last_error = 0;
static bool exit_in_progress = false;


static bool
_args_get(uc_vm_t *vm, bool named, size_t nargs, ...)
{
	uc_value_t **ptr, *arg, *obj = NULL;
	uc_type_t type, t;
	const char *name;
	size_t index = 0;
	va_list ap;
	int opt;

	if (named) {
		obj = uc_fn_arg(0);

		if (nargs != 1 || ucv_type(obj) != UC_OBJECT)
			named = false;
	}

	va_start(ap, nargs);

	while (true) {
		name = va_arg(ap, const char *);

		if (!name)
			break;

		type = va_arg(ap, uc_type_t);
		opt = va_arg(ap, int);
		ptr = va_arg(ap, uc_value_t **);

		if (named)
			arg = ucv_object_get(obj, name, NULL);
		else
			arg = uc_fn_arg(index++);

		t = ucv_type(arg);

		if (t == UC_CFUNCTION)
			t = UC_CLOSURE;

		if (arg && t != type) {
			last_error = -1;
			va_end(ap);
			return false;
		}

		if (!arg && opt == REQUIRED) {
			last_error = -1;
			va_end(ap);
			return false;
		}

		*ptr = arg;
	}

	va_end(ap);
	return true;
}

#define args_get_named(vm, nargs, ...) do { if (!_args_get(vm, true, nargs, __VA_ARGS__, NULL)) return NULL; } while(0)
#define args_get(vm, nargs, ...) do { if (!_args_get(vm, false, nargs, __VA_ARGS__, NULL)) return NULL; } while(0)

/* Callbacks live in the extended resource's embedded value slots: plain C
 * struct fields are invisible to the mark-and-sweep GC and would be freed
 * under ucode -g even with a positive refcount. */
enum {
	SLOT_ON_CONNECT,
	SLOT_ON_RECONNECT,
	SLOT_ON_DISCONNECT,
	SLOT_ON_ERROR,
	SLOT_ON_RECV,
	SLOT_ON_DRAIN,
	SLOT_MAX
};

typedef struct {
	uwsc_client_t *client;
	struct uloop_timeout connect_timer;
	struct uloop_timeout reconnect_timer;
	struct uloop_timeout release_timer;
	char *url;
	uwsc_client_config_t config;
	uc_vm_t *vm;
	uc_value_t *res_obj;
	bool is_reconnecting;
	bool closed;
} uwsc_ws_connection_t;

static void start_reconnect_timer(uwsc_ws_connection_t *conn);
static void reconnect_cb(struct uloop_timeout *timer);

static void
uwsc_ws_connection_free(void *ptr)
{
	uwsc_ws_connection_t *conn = ptr;

	if (conn->client) {
		uwsc_client_destroy(conn->client);
	}

	uloop_timeout_cancel(&conn->connect_timer);
	uloop_timeout_cancel(&conn->reconnect_timer);
	uloop_timeout_cancel(&conn->release_timer);
	free(conn->url);

	if (conn->config.protocols) {
		for (size_t i = 0; i < conn->config.protocol_count; i++)
			free(conn->config.protocols[i]);
		free(conn->config.protocols);
	}
	free(conn->config.ca_cert_path);
	free(conn->config.user_agent);

	/* Slot values are released by the runtime; conn itself is part of the
	 * resource allocation and must not be freed here */
	ucv_put(conn->res_obj);
}

/* Invoke the callback stored in `slot`. The connection object is always the
 * first argument; `arg` is an optional second argument whose reference is
 * consumed. Returns true if the callback called exit(). */
static bool
uwsc_ws_callback_call(uwsc_ws_connection_t *conn, size_t slot, uc_value_t *arg)
{
	bool prev_in_callback = false;
	uc_value_t *callback;
	int nargs = 1;

	/* res_obj is cleared once an explicitly closed connection is released;
	 * ucv_resource_value_get() would dereference the null */
	if (!conn->vm || !conn->res_obj) {
		ucv_put(arg);
		return false;
	}

	callback = ucv_resource_value_get(conn->res_obj, slot);

	if (!callback || !ucv_is_callable(callback)) {
		ucv_put(arg);
		return false;
	}

	/* Push this object (null for standalone function) */
	uc_vm_stack_push(conn->vm, NULL);
	/* Push function */
	uc_vm_stack_push(conn->vm, ucv_get(callback));
	/* Push arguments */
	uc_vm_stack_push(conn->vm, ucv_get(conn->res_obj));
	if (arg) {
		uc_vm_stack_push(conn->vm, arg);
		nargs = 2;
	}

	/* A disconnect surfacing inside the callback must defer the client
	 * destruction: C frames up the stack still hold the pointer */
	if (conn->client) {
		prev_in_callback = conn->client->in_callback;
		conn->client->in_callback = true;
	}

	uc_exception_type_t ex = uc_vm_call(conn->vm, true, nargs);

	if (conn->client)
		conn->client->in_callback = prev_in_callback;

	if (ex == EXCEPTION_NONE) {
		ucv_put(uc_vm_stack_pop(conn->vm));
		return false;
	} else if (ex == EXCEPTION_EXIT) {
		/* exit() was called - stop uloop immediately */
		exit_in_progress = true;
		uloop_end();
		return true;
	}
	return false;
}

__hidden bool
uwsc_ucode_on_connect(uwsc_client_t *client)
{
	uwsc_ws_connection_t *conn = client->ucode_ctx;
	size_t slot = SLOT_ON_CONNECT;

	if (exit_in_progress || !conn)
		return false;

	/* Use on_reconnect if reconnecting and available, otherwise on_connect */
	if (conn->is_reconnecting &&
	    ucv_resource_value_get(conn->res_obj, SLOT_ON_RECONNECT))
		slot = SLOT_ON_RECONNECT;

	if (uwsc_ws_callback_call(conn, slot, NULL))
		return true;

	conn->is_reconnecting = false;
	return false;
}

__hidden bool
uwsc_ucode_on_disconnect(uwsc_client_t *client)
{
	uwsc_ws_connection_t *conn = client->ucode_ctx;

	if (exit_in_progress || !conn)
		return false;

	if (uwsc_ws_callback_call(conn, SLOT_ON_DISCONNECT, NULL))
		return true;

	if (client->in_callback) {
		client->state = UWSC_CLIENT_STATE_DISCONNECTED;
	} else {
		uwsc_client_destroy(conn->client);
		conn->client = NULL;
	}

	start_reconnect_timer(conn);
	return false;
}

__hidden bool
uwsc_ucode_on_error(uwsc_client_t *client, const char *error)
{
	uwsc_ws_connection_t *conn = client->ucode_ctx;

	if (exit_in_progress || !conn)
		return false;

	if (uwsc_ws_callback_call(conn, SLOT_ON_ERROR, ucv_string_new(error)))
		return true;

	/* Mirror uwsc_ucode_on_disconnect(): tear down the failed client and
	 * arm the reconnect timer. Without this the connection stays stuck
	 * with conn->client referencing a dead object whose fd may still sit
	 * in uloop, and never retries. */
	if (client->in_callback) {
		client->state = UWSC_CLIENT_STATE_DISCONNECTED;
	} else {
		uwsc_client_destroy(conn->client);
		conn->client = NULL;
	}

	start_reconnect_timer(conn);
	return false;
}

__hidden bool
uwsc_ucode_on_recv(uwsc_client_t *client, const char *data, size_t len, bool binary)
{
	uwsc_ws_connection_t *conn = client->ucode_ctx;
	uc_value_t *msg_obj;

	if (exit_in_progress || !conn)
		return false;

	msg_obj = ucv_object_new(conn->vm);
	ucv_object_add(msg_obj, "data", ucv_string_new_length(data, len));
	ucv_object_add(msg_obj, "binary", ucv_boolean_new(binary));

	return uwsc_ws_callback_call(conn, SLOT_ON_RECV, msg_obj);
}

__hidden bool
uwsc_ucode_on_drain(uwsc_client_t *client)
{
	uwsc_ws_connection_t *conn = client->ucode_ctx;

	if (exit_in_progress || !conn)
		return false;

	return uwsc_ws_callback_call(conn, SLOT_ON_DRAIN, NULL);
}


static void
attempt_connection(uwsc_ws_connection_t *conn)
{
	/* A disconnect inside a callback defers the destruction of the old
	 * client; complete it now, outside any callback stack */
	if (conn->client) {
		uwsc_client_destroy(conn->client);
		conn->client = NULL;
	}

	conn->client = uwsc_client_create(&conn->config);
	if (!conn->client) {
		start_reconnect_timer(conn);
		return;
	}

	/* Store connection context for callbacks */
	conn->client->ucode_ctx = conn;

	int ret = uwsc_client_connect(conn->client, conn->url);
	if (ret != 0) {
		uwsc_client_destroy(conn->client);
		conn->client = NULL;
		start_reconnect_timer(conn);
	}
}

static void
start_reconnect_timer(uwsc_ws_connection_t *conn)
{
	/* close() may run inside on_error or on_disconnect, whose callers arm
	 * the reconnect after the callback returns */
	if (conn->closed)
		return;

	if (conn->config.reconnect_timeout > 0) {
		conn->is_reconnecting = true;
		conn->reconnect_timer.cb = reconnect_cb;
		uloop_timeout_set(&conn->reconnect_timer, conn->config.reconnect_timeout);
	}
}

static void
reconnect_cb(struct uloop_timeout *timer)
{
	uwsc_ws_connection_t *conn = container_of(timer, uwsc_ws_connection_t, reconnect_timer);
	attempt_connection(conn);
}

static void
deferred_connect_cb(struct uloop_timeout *timer)
{
	uwsc_ws_connection_t *conn = container_of(timer, uwsc_ws_connection_t, connect_timer);
	attempt_connection(conn);
}

/* Undo what uc_ws_connect() pinned. Both halves have to go: `persistent` keeps
 * the resource in the GC root set, and res_obj is a self-reference that on its
 * own holds the refcount above zero, so releasing either alone leaks.
 *
 * This runs from a timeout rather than directly from close() because close()
 * is commonly called from inside a callback, whose C frames are still
 * dereferencing the client. By the time a uloop timeout fires, that stack has
 * unwound. Nothing may touch conn after the put: it may be freed there. */
static void
release_cb(struct uloop_timeout *timer)
{
	uwsc_ws_connection_t *conn = container_of(timer, uwsc_ws_connection_t, release_timer);
	uc_value_t *obj = conn->res_obj;

	if (!obj)
		return;

	conn->res_obj = NULL;
	ucv_resource_persistent_set(obj, false);
	ucv_put(obj);
}

static uc_value_t *uc_ws_connect(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *url_val, *config_obj, *obj;
	uc_value_t *timeout_val, *ssl_verify_val, *user_agent_val, *protocol_val;
	uc_value_t *on_connect_val, *on_reconnect_val, *on_disconnect_val, *on_error_val, *on_recv_val;
	uc_value_t *on_drain_val = NULL;
	uwsc_ws_connection_t *conn;
	const char *url, *proto, *user_agent;

	/* Get positional arguments first */
	args_get(vm, nargs,
		"url", UC_STRING, REQUIRED, &url_val,
		"config", UC_OBJECT, OPTIONAL, &config_obj);

	/* Parse named config arguments from config object */
	uc_value_t *ping_timeout_val = NULL;
	uc_value_t *idle_timeout_val = NULL;
	uc_value_t *reconnect_timeout_val = NULL;
	uc_value_t *ca_cert_val = NULL;
	if (config_obj) {
		args_get_named(vm, 1,
			"connection_timeout", UC_INTEGER, OPTIONAL, &timeout_val,
			"ping_timeout", UC_INTEGER, OPTIONAL, &ping_timeout_val,
			"idle_timeout", UC_INTEGER, OPTIONAL, &idle_timeout_val,
			"reconnect_timeout", UC_INTEGER, OPTIONAL, &reconnect_timeout_val,
			"ssl_verify", UC_BOOLEAN, OPTIONAL, &ssl_verify_val,
			"ca_cert", UC_STRING, OPTIONAL, &ca_cert_val,
			"user_agent", UC_STRING, OPTIONAL, &user_agent_val,
			"protocol", UC_STRING, OPTIONAL, &protocol_val,
			"on_connect", UC_CLOSURE, OPTIONAL, &on_connect_val,
			"on_reconnect", UC_CLOSURE, OPTIONAL, &on_reconnect_val,
			"on_disconnect", UC_CLOSURE, OPTIONAL, &on_disconnect_val,
			"on_error", UC_CLOSURE, OPTIONAL, &on_error_val,
			"on_recv", UC_CLOSURE, OPTIONAL, &on_recv_val,
			"on_drain", UC_CLOSURE, OPTIONAL, &on_drain_val);
	}

	url = ucv_string_get(url_val);
	if (!url)
		return NULL;

	obj = ucv_resource_create_ex(vm, "uwsc.connection", (void **)&conn,
	                             SLOT_MAX, sizeof(*conn));
	if (!obj)
		return NULL;

	conn->vm = vm;
	conn->res_obj = ucv_get(obj);
	conn->url = xstrdup(url);

	/* Parse config values */
	if (timeout_val)
		conn->config.timeout_connect = ucv_uint64_get(timeout_val);

	if (ping_timeout_val)
		conn->config.ping_timeout = ucv_uint64_get(ping_timeout_val);

	/* idle_timeout: ms of inbound silence before the connection is torn
	 * down. An explicit 0 disables the timer entirely; an omitted option
	 * keeps the legacy 60s default. */
	if (idle_timeout_val)
		conn->config.timeout_idle = ucv_uint64_get(idle_timeout_val);
	else
		conn->config.timeout_idle = 60000;

	if (reconnect_timeout_val)
		conn->config.reconnect_timeout = ucv_uint64_get(reconnect_timeout_val);

	/* Default to true for security - users must explicitly disable verification */
	conn->config.ssl_verify = ssl_verify_val ? ucv_boolean_get(ssl_verify_val) : true;

	if (ca_cert_val) {
		const char *ca_cert = ucv_string_get(ca_cert_val);
		if (ca_cert)
			conn->config.ca_cert_path = xstrdup(ca_cert);
	}

	if (user_agent_val) {
		user_agent = ucv_string_get(user_agent_val);
		if (user_agent)
			conn->config.user_agent = xstrdup(user_agent);
	}

	/* Protocol configuration */
	if (protocol_val) {
		proto = ucv_string_get(protocol_val);
		if (proto) {
			conn->config.protocols = xalloc(sizeof(char *));
			conn->config.protocols[0] = xstrdup(proto);
			conn->config.protocol_count = 1;
		}
	}

	/* Store callbacks in GC-visible slots */
	if (on_connect_val)
		ucv_resource_value_set(obj, SLOT_ON_CONNECT, ucv_get(on_connect_val));

	if (on_reconnect_val)
		ucv_resource_value_set(obj, SLOT_ON_RECONNECT, ucv_get(on_reconnect_val));

	if (on_disconnect_val)
		ucv_resource_value_set(obj, SLOT_ON_DISCONNECT, ucv_get(on_disconnect_val));

	if (on_error_val)
		ucv_resource_value_set(obj, SLOT_ON_ERROR, ucv_get(on_error_val));

	if (on_recv_val)
		ucv_resource_value_set(obj, SLOT_ON_RECV, ucv_get(on_recv_val));

	if (on_drain_val)
		ucv_resource_value_set(obj, SLOT_ON_DRAIN, ucv_get(on_drain_val));

	/* uloop drives the connection from here on; the script may drop its
	 * reference, so shield the resource from the GC */
	ucv_resource_persistent_set(obj, true);

	/* Set up deferred connection timer */
	conn->connect_timer.cb = deferred_connect_cb;
	uloop_timeout_set(&conn->connect_timer, 1);

	return obj;
}

static uc_value_t *uc_ws_send(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data_val = uc_fn_arg(0);
	uc_value_t *binary_val = uc_fn_arg(1);
	uwsc_ws_connection_t *conn;
	const char *data = NULL;
	char *json_str = NULL;
	size_t len;
	bool binary = false;
	int ret;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn || !conn->client)
		return ucv_boolean_new(false);

	/* Check if data_val is a string */
	data = ucv_string_get(data_val);

	if (data) {
		len = ucv_string_length(data_val);
	}
	/* If not a string, check if it's an object or array and convert to JSON */
	else {
		if (ucv_type(data_val) == UC_OBJECT || ucv_type(data_val) == UC_ARRAY) {
			json_str = ucv_to_jsonstring(vm, data_val);
			if (json_str) {
				data = json_str;
				len = strlen(json_str);
			}
		}
	}

	if (!data)
		return ucv_boolean_new(false);

	if (binary_val)
		binary = ucv_boolean_get(binary_val);

	ret = uwsc_client_send(conn->client, data, len, binary);

	if (json_str)
		free(json_str);

	return ucv_boolean_new(ret == 0);
}

static uc_value_t *uc_ws_close(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *code_val = uc_fn_arg(0);
	uc_value_t *reason_val = uc_fn_arg(1);
	uwsc_ws_connection_t *conn;
	uint16_t code = 1000;
	const char *reason = NULL;
	int ret;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn)
		return ucv_boolean_new(false);

	if (code_val)
		code = ucv_uint64_get(code_val);

	if (reason_val)
		reason = ucv_string_get(reason_val);

	conn->closed = true;
	uloop_timeout_cancel(&conn->connect_timer);
	uloop_timeout_cancel(&conn->reconnect_timer);

	/* An explicitly closed connection is finished with; drop the pin that
	 * keeps it alive so the runtime can reclaim it once the script lets go.
	 * Deferred, see release_cb().
	 *
	 * This happens whether or not there is a live client to close. A
	 * connection closed before its deferred connect ran, or one whose
	 * client an error already destroyed, has nothing to shut down but is
	 * still pinned. */
	conn->release_timer.cb = release_cb;
	uloop_timeout_set(&conn->release_timer, 0);

	if (!conn->client)
		return ucv_boolean_new(false);

	ret = uwsc_client_close(conn->client, code, reason);

	return ucv_boolean_new(ret == 0);
}

static uc_value_t *uc_ws_receive(uc_vm_t *vm, size_t nargs)
{
	uwsc_ws_connection_t *conn;
	char *data;
	size_t len;
	bool binary = true;
	int ret;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn || !conn->client)
		return NULL;

	ret = uwsc_client_ws_receive_sync(conn->client, &data, &len, &binary);
	if (ret != 0)
		return NULL;

	uc_value_t *result = ucv_object_new(vm);
	ucv_object_add(result, "data", ucv_string_new_length(data, len));
	ucv_object_add(result, "binary", ucv_boolean_new(binary));

	free(data);
	return result;
}

static uc_value_t *uc_ws_state(uc_vm_t *vm, size_t nargs)
{
	uwsc_ws_connection_t *conn;
	uwsc_client_state_t state;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn)
		return ucv_string_new("disconnected");

	if (!conn->client)
		return ucv_string_new("pending");

	state = uwsc_client_get_state(conn->client);

	switch (state) {
	case UWSC_CLIENT_STATE_DISCONNECTED: return ucv_string_new("disconnected");
	case UWSC_CLIENT_STATE_DNS_RESOLVE: return ucv_string_new("resolving");
	case UWSC_CLIENT_STATE_TCP_CONNECT: return ucv_string_new("connecting");
	case UWSC_CLIENT_STATE_SSL_HANDSHAKE: return ucv_string_new("ssl_handshake");
	case UWSC_CLIENT_STATE_HTTP_UPGRADE: return ucv_string_new("upgrading");
	case UWSC_CLIENT_STATE_WS_HANDSHAKE: return ucv_string_new("handshake");
	case UWSC_CLIENT_STATE_CONNECTED: return ucv_string_new("connected");
	case UWSC_CLIENT_STATE_CLOSING: return ucv_string_new("closing");
	case UWSC_CLIENT_STATE_ERROR: return ucv_string_new("error");
	default: return ucv_string_new("unknown");
	}
}

static uc_value_t *uc_ws_is_connected(uc_vm_t *vm, size_t nargs)
{
	uwsc_ws_connection_t *conn;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn || !conn->client)
		return ucv_boolean_new(false);

	return ucv_boolean_new(uwsc_client_get_state(conn->client) == UWSC_CLIENT_STATE_CONNECTED);
}

static uc_value_t *uc_ws_pending(uc_vm_t *vm, size_t nargs)
{
	uwsc_ws_connection_t *conn;

	conn = uc_fn_thisval("uwsc.connection");
	if (!conn || !conn->client)
		return ucv_uint64_new(0);

	return ucv_uint64_new(uwsc_client_send_buffer_pending(conn->client));
}

static const uc_function_list_t ws_module_functions[] = {
	{ "connect", uc_ws_connect }
};

static const uc_function_list_t ws_connection_methods[] = {
	{ "send", uc_ws_send },
	{ "receive", uc_ws_receive },
	{ "close", uc_ws_close },
	{ "state", uc_ws_state },
	{ "is_connected", uc_ws_is_connected },
	{ "pending", uc_ws_pending }
};

void uc_module_entry(uc_vm_t *vm, uc_value_t *scope) __attribute__((used));
void uc_module_entry(uc_vm_t *vm, uc_value_t *scope)
{
	uc_type_declare(vm, "uwsc.connection", ws_connection_methods, uwsc_ws_connection_free);
	uc_function_list_register(scope, ws_module_functions);
}
