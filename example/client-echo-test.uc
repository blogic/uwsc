#!/usr/bin/env ucode
/*
 * Simple WebSocket echo test
 * Usage: ucode client-echo-test.uc
 */

import * as ws from 'uwsc';
import * as uloop from 'uloop';

printf("Initializing uloop...\n");
uloop.init();

let url = "wss://echo.websocket.org";
printf("Connecting to: %s\n", url);

let conn = ws.connect(url, {
    connection_timeout: 5000,
    on_connect: function(conn) {
        printf("Connected to echo server!\n");
        // Send a test message
        let message = "Hello WebSocket Echo!";
        printf("Sending: %s\n", message);
        conn.send(message);
    },
    on_disconnect: function(conn) {
        printf("Connection closed\n");
        uloop.end();
    },
    on_error: function(conn, error) {
        printf("Error: %s\n", error);
        uloop.end();
    },
    on_recv: function(conn, message) {
        printf("Received: %s\n", message.data);
        // Close connection after receiving message
        conn.close();
    }
});

if (!conn) {
    printf("Connection failed\n");
    exit(1);
}

printf("Connection initiated. State: %s\n", conn.state());
uloop.run();
