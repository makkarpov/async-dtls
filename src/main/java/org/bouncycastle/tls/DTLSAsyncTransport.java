package org.bouncycastle.tls;

import java.io.IOException;

public interface DTLSAsyncTransport extends DatagramSender {
    /**
     * Send datagram to the remote peer. Supplied array is guaranteed to remain valid after the call, so no defensive
     * copies are required.
     *
     * @param buf   Data to send
     * @param off   Offset to the first byte of data
     * @param len   Length of datagram
     */
    void send(byte[] buf, int off, int len) throws IOException; // overridden to specify additional guarantees

    /**
     * Flush transport, allowing multiple records to be grouped in single datagram.
     *
     * @param isRetransmit RFC states that retransmissions should preferably use smaller datagrams. So this flag can be
     *                     used to disable datagram buffering in such cases.
     */
    void flush(boolean isRetransmit) throws IOException;

    /**
     * @return Maximum input datagram size that DTLS stack should expect
     */
    int getReceiveLimit() throws IOException;

    /**
     * Invoked when exception was caught in asynchronous events, e.g. in timer tasks.
     * All exceptions are considered fatal.
     */
    void exceptionCaught(Throwable cause);

    /**
     * Close the transport
     */
    void close() throws IOException;
}
