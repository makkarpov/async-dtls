package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InterruptedIOException;

/**
 * Note that, despite being non-blocking, DTLS stack and this particular class are *not* thread-safe. Class methods must
 * not be invoked concurrently, even through {@link TlsTimer} tasks. This was done to improve performance in situations
 * where underlying threading model (such as Netty's one) permits writing handlers as-if they are single threaded. If
 * concurrency is an issue, this class and provided timer object must be synchronized externally.
 */
public class DTLSAsyncProtocol {
    private final DTLSAsyncTransport transport;
    private final DTLSRecordLayer recordLayer;
    private final TlsContext context;

    private DTLSAsyncHandshake handshake;

    DTLSAsyncProtocol(DTLSAsyncHandshake handshake, DTLSAsyncTransport transport) throws IOException {
        this.handshake = handshake;
        this.transport = transport;

        context = handshake.context();
        recordLayer = handshake.recordLayer();
    }

    public TlsContext context() {
        return context;
    }

    public boolean handshakeCompleted() {
        return handshake == null;
    }

    public int getSendLimit() throws IOException {
        return recordLayer.getSendLimit();
    }

    public int getReceiveLimit() throws IOException {
        return recordLayer.getReceiveLimit();
    }

    /**
     * Push received datagram for processing. This may result in events signalled on the transport and/or decoded
     * application data. Application data must then be retrieved via repeated calls to
     *
     * @param buf   Buffer with received datagram
     * @param off   Offset within a buffer
     * @param len   Length of the datagram
     */
    public void pushReceivedDatagram(byte[] buf, int off, int len) throws IOException {
        if (handshake != null) {
            try {
                handshake.pushReceivedDatagram(buf, off, len);
            } catch (TlsFatalAlert alert) {
                handshake.abort(alert.alertDescription);
                throw alert;
            } catch (IOException e) {
                handshake.abort(AlertDescription.internal_error);
                throw e;
            } catch (Exception e) {
                handshake.abort(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }

            if (handshake.handshakeCompleted()) {
                handshake.clear();
                handshake = null;
            }
        } else {
            recordLayer.pushReceivedDatagram(buf, off, len);
        }
    }

    public int receive(byte[] buf, int off, int len) throws IOException {
        if (handshake != null) {
            return -1;
        }

        try {
            return recordLayer.receive(buf, off, len);
        } catch (Exception e) {
            throw handleException(recordLayer, e);
        }
    }

    public void send(byte[] buf, int off, int len) throws IOException {
        if (handshake != null) {
            throw new IllegalStateException("Cannot send application data while handshake is in progress");
        }

        try {
            recordLayer.send(buf, off, len);
            transport.flush(false);
        } catch (Exception e) {
            throw handleException(recordLayer, e);
        }
    }

    public void close() throws IOException {
        recordLayer.close();
    }

    DTLSRecordLayer getRecordLayer() {
        return recordLayer;
    }

    static IOException handleException(DTLSRecordLayer recordLayer, Throwable cause) {
        if (cause instanceof TlsFatalAlert) {
            recordLayer.fail(((TlsFatalAlert) cause).getAlertDescription());
            return (TlsFatalAlert) cause;
        }

        if (cause instanceof InterruptedIOException) {
            return (InterruptedIOException) cause;
        }

        if (cause instanceof IOException) {
            recordLayer.fail(AlertDescription.internal_error);
            return (IOException) cause;
        }

        recordLayer.fail(AlertDescription.internal_error);
        return new TlsFatalAlert(AlertDescription.internal_error, cause);
    }
}
