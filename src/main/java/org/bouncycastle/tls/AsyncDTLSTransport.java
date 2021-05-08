package org.bouncycastle.tls;

public interface AsyncDTLSTransport extends DatagramSender {
    /**
     * Invoked when asynchronous exception has been caught in timer task.
     *
     * @param cause Caught exception
     */
    void exceptionCaught(Throwable cause);

    /**
     * Invoked when application data was decoded during message processing.
     *
     * @param buffer    Data buffer, valid only during call
     * @param offset    Data offset in buffer
     * @param length    Data length in buffer
     */
    void applicationDataReceived(byte[] buffer, int offset, int length);

    /**
     * Close underlying transport
     */
    void close();
}
