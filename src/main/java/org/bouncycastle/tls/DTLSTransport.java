package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

/**
 * Blocking wrapper over asynchronous DTLS engine and blocking sockets
 */
public class DTLSTransport
    implements DatagramTransport
{
    private static final int MAX_TIMERS = 4; // 1 in record layer, 3 in reliable handshake

    private static class TimerTaskImpl implements TlsTimer.TaskHandle {
        boolean isActive;
        Timeout timeout;
        Runnable target;

        @Override
        public void cancel() {
            isActive = false;
            target = null;
            timeout = null;
        }
    }

    private static class AsyncTransportImpl implements DTLSAsyncTransport {
        private final DatagramTransport transport;
        Throwable bufferedException;

        public AsyncTransportImpl(DatagramTransport transport) {
            this.transport = transport;
        }

        @Override
        public void send(byte[] buf, int off, int len) throws IOException {
            transport.send(buf, off, len);
        }

        @Override
        public void flush(boolean isRetransmit) throws IOException {
        }

        @Override
        public int getReceiveLimit() throws IOException {
            return transport.getReceiveLimit();
        }

        @Override
        public void exceptionCaught(Throwable cause) {
            bufferedException = cause;
        }

        @Override
        public void close() throws IOException {
            transport.close();
        }

        @Override
        public int getSendLimit() throws IOException {
            return transport.getSendLimit();
        }
    }

    private static class TlsTimerImpl implements TlsTimer {
        private final TimerTaskImpl[] timerTasks = new TimerTaskImpl[MAX_TIMERS];

        public TlsTimerImpl() {
            for (int i = 0; i < timerTasks.length; i++) {
                timerTasks[i] = new TimerTaskImpl();
            }
        }

        @Override
        public TaskHandle schedule(Runnable target, int delayMillis) {
            for (int i = 0; i < timerTasks.length; i++) {
                if (!timerTasks[i].isActive) {
                    timerTasks[i].isActive = true;
                    timerTasks[i].target = target;
                    timerTasks[i].timeout = new Timeout(delayMillis);
                    return timerTasks[i];
                }
            }

            throw new IllegalStateException("All timer slots are occupied");
        }

        /**
         * Check and execute all ready tasks, and compute wait time for remaining.
         *
         * @return Wait time in milliseconds, or 0 if no timers are set
         */
        public int checkTasks() {
            int result = 0;
            long currentMillis = System.currentTimeMillis();

            for (int i = 0; i < timerTasks.length; i++) {
                if (!timerTasks[i].isActive) {
                    continue;
                }

                if (Timeout.hasExpired(timerTasks[i].timeout, currentMillis)) {
                    timerTasks[i].target.run();
                    timerTasks[i].cancel();
                } else {
                    int thisMillis = Math.max(1, Timeout.getWaitMillis(timerTasks[i].timeout, currentMillis));

                    if (result == 0) {
                        result = thisMillis;
                    } else {
                        result = Math.min(thisMillis, result);
                    }
                }
            }

            return result;
        }
    }

    private final TlsTimerImpl timer;
    private final DatagramTransport datagramTransport;
    private final AsyncTransportImpl transport;
    private DTLSAsyncProtocol protocol;
    private byte[] datagramBuffer;

    DTLSTransport(DatagramTransport transport)
    {
        this.timer = new TlsTimerImpl();
        this.datagramTransport = transport;
        this.transport = new AsyncTransportImpl(transport);
    }

    TlsTimer getTimer() {
        return timer;
    }

    DTLSAsyncTransport getTransport() {
        return transport;
    }

    void setProtocol(DTLSAsyncProtocol protocol) throws IOException {
        this.protocol = protocol;
        this.datagramBuffer = new byte[protocol.getReceiveLimit()];
    }

    private void receiveDatagram(int waitMillis) throws IOException {
        while (true) {
            int timerWait = timer.checkTasks();

            if (transport.bufferedException != null) {
                IOException handled = DTLSAsyncProtocol.handleException(protocol.getRecordLayer(),
                        transport.bufferedException);

                transport.bufferedException = null;
                throw handled;
            }

            if (waitMillis > 0) {
                timerWait = Math.min(timerWait, waitMillis);
            }

            int received;
            try {
                received = datagramTransport.receive(datagramBuffer, 0, datagramBuffer.length, timerWait);
            } catch (SocketTimeoutException ignored) {
                // Just do timer tasks and try again
                continue;
            }

            if (received > 0) {
                protocol.pushReceivedDatagram(datagramBuffer, 0, received);
                return;
            }
        }
    }

    void completeHandshake() throws IOException {
        while (!protocol.handshakeCompleted()) {
            receiveDatagram(0);
        }
    }

    // Public interface methods:

    public TlsContext getContext() {
        return protocol.context();
    }

    public int getReceiveLimit()
        throws IOException
    {
        return protocol.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return protocol.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        if (null == buf)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || off >= buf.length)
        {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        }
        if (len < 0 || len > buf.length - off)
        {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        }
        if (waitMillis < 0)
        {
            throw new IllegalArgumentException("'waitMillis' cannot be negative");
        }

        while (true) {
            int received = protocol.receive(buf, off, len);
            if (received >= 0) {
                return received;
            }

            receiveDatagram(waitMillis);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (null == buf)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || off >= buf.length)
        {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        }
        if (len < 0 || len > buf.length - off)
        {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        }

        protocol.send(buf, off, len);
    }

    public void close()
        throws IOException
    {
        protocol.close();
    }
}
