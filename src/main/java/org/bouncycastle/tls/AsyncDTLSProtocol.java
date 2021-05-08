package org.bouncycastle.tls;

import java.io.IOException;

/**
 * All components of async-DTLS code are *not* thread-safe. This is done to improve performance in scenarios where
 * underlying threading model itself guarantees synchronization, usually by attaching socket to specific event loop.
 * This also applies to timer as well. All scheduled runnables must be invoked synchronously. If concurrency is a
 * concern, access to async DTLS stack must be synchronized externally.
 */
public class AsyncDTLSProtocol {
    private AsyncDTLSTransport transport;
    private AsyncDTLSHandshake handshake;
    private AsyncDTLSRecordLayer recordLayer;

    private AsyncDTLSProtocol(AsyncDTLSTransport transport, AsyncDTLSHandshake handshake) throws IOException {
        this.transport = transport;
        this.handshake = handshake;
    }

    /**
     * Push received data for processing. This will result in events generated in transport object.
     *
     * @param data  Received data buffer
     * @param off   Offset in buffer
     * @param len   Data length
     */
    public void pushReceivedData(byte[] data, int off, int len) {
        if (handshake != null) {
            handshake.pushReceivedData(data, off, len);
            if (handshake.handshakeCompleted()) {
                recordLayer = handshake.getRecordLayer();
                handshake = null;
            }
        }

        if (recordLayer != null) {
            throw new IllegalStateException("i can't decode :(");
        }
    }

    public static AsyncDTLSProtocol server(TlsServer server, TlsTimer timer, AsyncDTLSTransport transport)
            throws IOException {
        return server(server, timer, transport, null);
    }

    public static AsyncDTLSProtocol server(TlsServer server, TlsTimer timer, AsyncDTLSTransport transport,
                                           DTLSRequest request) throws IOException {
        return new AsyncDTLSProtocol(transport, new AsyncDTLSServerHandshake(server, timer, transport, request));
    }
}
