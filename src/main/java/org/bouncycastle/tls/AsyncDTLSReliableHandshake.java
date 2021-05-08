package org.bouncycastle.tls;

import org.bouncycastle.util.Integers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

/**
 * This class is *not* thread-safe.
 * @see AsyncDTLSProtocol
 */
class AsyncDTLSReliableHandshake {
    private static final int MAX_RECEIVE_AHEAD = 16;
    private static final int MESSAGE_HEADER_LENGTH = 12;

    private static final int INITIAL_RESEND_MILLIS = 1000;
    private static final int MAX_RESEND_MILLIS = 60000;

    private TlsContext context;
    private AsyncDTLSRecordLayer transport;
    private TlsHandshakeHash handshakeHash;

    private TlsTimer.TimerTask resendTimeout;
    private TlsTimer.TimerTask handshakeTimeout;
    private int resendMillis = -1;
    private Runnable resendRunnable;

    private Hashtable currentInboundFlight = new Hashtable();
    private Hashtable previousInboundFlight = null;
    private Vector outboundFlight = new Vector();

    private boolean stopped;
    private int nextSendSeq, nextReceiveSeq;
    private byte[] recordBuffer;

    public AsyncDTLSReliableHandshake(TlsContext context, AsyncDTLSRecordLayer transport, DTLSRequest request,
                                      int timeoutMillis) {
        this.transport = transport;
        this.context = context;
        this.handshakeHash = new DeferredHash(context);

        this.resendRunnable = new Runnable() {
            @Override
            public void run() {
                resendTimeout = null; // mark the timeout as triggered
                try {
                    resendOutboundFlight();
                } catch (IOException e) {
                    transport.getTransport().exceptionCaught(e);
                }
            }
        };

        if (timeoutMillis > 0) {
            handshakeTimeout = transport.getTimer().schedule(
                    new Runnable() {
                        @Override
                        public void run() {
                            transport.getTransport().exceptionCaught(new Exception("Handshake timeout"));
                        }
                    },
                    timeoutMillis
            );
        }

        recordBuffer = new byte[AsyncDTLSRecordLayer.MAX_FRAGMENT_LENGTH];

        if (null != request) {
            // @makkarpov: We haven't initialized any outbound flight. What to resend?
            resendMillis = DTLSReliableHandshake.INITIAL_RESEND_MILLIS;
            scheduleResend();

            long recordSeq = request.getRecordSeq();
            int messageSeq = request.getMessageSeq();
            byte[] message = request.getMessage();

            transport.resetAfterHelloVerifyRequestServer(recordSeq);

            // Simulate a previous flight consisting of the request ClientHello
            DTLSReassembler reassembler = new DTLSReassembler(HandshakeType.client_hello, message.length - MESSAGE_HEADER_LENGTH);
            currentInboundFlight.put(Integers.valueOf(messageSeq), reassembler);

            // We sent HelloVerifyRequest with (message) sequence number 0
            nextSendSeq = 1;
            nextReceiveSeq = messageSeq + 1;

            handshakeHash.update(message, 0, message.length);
        }
    }

    private void cancelResend() {
        if (resendTimeout != null) {
            resendTimeout.cancel();
            resendTimeout = null;
        }
    }

    private void scheduleResend() {
        cancelResend();
        resendTimeout = transport.getTimer().schedule(resendRunnable, resendMillis);
    }

    TlsHandshakeHash getHandshakeHash()
    {
        return handshakeHash;
    }

    TlsHandshakeHash prepareToFinish()
    {
        TlsHandshakeHash result = handshakeHash;
        this.handshakeHash = handshakeHash.stopTracking();
        return result;
    }

    void sendMessage(short msg_type, byte[] body) 
            throws IOException 
    {
        TlsUtils.checkUint24(body.length);

        if (null != resendTimeout)
        {
            checkInboundFlight();

            resendMillis = -1;
            cancelResend();

            outboundFlight.removeAllElements();
        }

        Message message = new Message(nextSendSeq++, msg_type, body);

        outboundFlight.addElement(message);

        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }
    
    Message receiveMessage()
            throws IOException
    {
        if (null == resendTimeout)
        {
            resendMillis = INITIAL_RESEND_MILLIS;
            scheduleResend();

            prepareInboundFlight(new Hashtable());
        }

        if (transport.isClosed())
        {
            throw new TlsFatalAlert(AlertDescription.user_canceled);
        }

        while (true) {
            Message pending = getPendingMessage();
            if (pending != null) {
                return pending;
            }

            int received = transport.receive(recordBuffer, 0);
            if (received < 0) {
                return null;
            }

            processRecord(MAX_RECEIVE_AHEAD, transport.getReadEpoch(), recordBuffer, 0, received);
        }
    }

    void finish()
    {
        DTLSHandshakeRetransmit retransmit = null;
        if (null != resendTimeout)
        {
            checkInboundFlight();
        }
        else
        {
            prepareInboundFlight(null);

            if (previousInboundFlight != null)
            {
                /*
                 * RFC 6347 4.2.4. In addition, for at least twice the default MSL defined for [TCP],
                 * when in the FINISHED state, the node that transmits the last flight (the server in an
                 * ordinary handshake or the client in a resumed handshake) MUST respond to a retransmit
                 * of the peer's last flight with a retransmit of the last flight.
                 */
                retransmit = new DTLSHandshakeRetransmit()
                {
                    public void receivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
                            throws IOException
                    {
                        processRecord(0, epoch, buf, off, len);
                    }
                };
            }
        }

        transport.handshakeSuccessful(retransmit);
    }

    public void stop() {
        stopped = true;
        cancelResend();
    }

    static int backOff(int timeoutMillis)
    {
        /*
         * TODO[DTLS] implementations SHOULD back off handshake packet size during the
         * retransmit backoff.
         */
        return Math.min(timeoutMillis * 2, MAX_RESEND_MILLIS);
    }

    /**
     * Check that there are no "extra" messages left in the current inbound flight
     */
    private void checkInboundFlight()
    {
        Enumeration e = currentInboundFlight.keys();
        while (e.hasMoreElements())
        {
            Integer key = (Integer)e.nextElement();
            if (key.intValue() >= nextReceiveSeq)
            {
                // TODO Should this be considered an error?
            }
        }
    }

    private Message getPendingMessage() throws IOException {
        DTLSReassembler next = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(nextReceiveSeq));
        if (next != null)
        {
            byte[] body = next.getBodyIfComplete();
            if (body != null)
            {
                previousInboundFlight = null;
                return updateHandshakeMessagesDigest(new Message(nextReceiveSeq++, next.getMsgType(), body));
            }
        }
        return null;
    }

    private void prepareInboundFlight(Hashtable nextFlight)
    {
        resetAll(currentInboundFlight);
        previousInboundFlight = currentInboundFlight;
        currentInboundFlight = nextFlight;
    }

    private void processRecord(int windowSize, int epoch, byte[] buf, int off, int len) throws IOException
    {
        boolean checkPreviousFlight = false;

        while (len >= MESSAGE_HEADER_LENGTH)
        {
            int fragment_length = TlsUtils.readUint24(buf, off + 9);
            int message_length = fragment_length + MESSAGE_HEADER_LENGTH;
            if (len < message_length)
            {
                // NOTE: Truncated message - ignore it
                break;
            }

            int length = TlsUtils.readUint24(buf, off + 1);
            int fragment_offset = TlsUtils.readUint24(buf, off + 6);
            if (fragment_offset + fragment_length > length)
            {
                // NOTE: Malformed fragment - ignore it and the rest of the record
                break;
            }

            /*
             * NOTE: This very simple epoch check will only work until we want to support
             * renegotiation (and we're not likely to do that anyway).
             */
            short msg_type = TlsUtils.readUint8(buf, off + 0);
            int expectedEpoch = msg_type == HandshakeType.finished ? 1 : 0;
            if (epoch != expectedEpoch)
            {
                break;
            }

            int message_seq = TlsUtils.readUint16(buf, off + 4);
            if (message_seq >= (nextReceiveSeq + windowSize))
            {
                // NOTE: Too far ahead - ignore
            }
            else if (message_seq >= nextReceiveSeq)
            {
                DTLSReassembler reassembler = (DTLSReassembler)currentInboundFlight.get(Integers.valueOf(message_seq));
                if (reassembler == null)
                {
                    reassembler = new DTLSReassembler(msg_type, length);
                    currentInboundFlight.put(Integers.valueOf(message_seq), reassembler);
                }

                reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset,
                        fragment_length);
            }
            else if (previousInboundFlight != null)
            {
                /*
                 * NOTE: If we receive the previous flight of incoming messages in full again,
                 * retransmit our last flight
                 */

                DTLSReassembler reassembler = (DTLSReassembler)previousInboundFlight.get(Integers.valueOf(message_seq));
                if (reassembler != null)
                {
                    reassembler.contributeFragment(msg_type, length, buf, off + MESSAGE_HEADER_LENGTH, fragment_offset,
                            fragment_length);
                    checkPreviousFlight = true;
                }
            }

            off += message_length;
            len -= message_length;
        }

        if (checkPreviousFlight && checkAll(previousInboundFlight))
        {
            resendOutboundFlight();
            resetAll(previousInboundFlight);
        }
    }

    private void resendOutboundFlight()
            throws IOException
    {
        if (stopped) {
            return;
        }

        transport.resetWriteEpoch();
        for (int i = 0; i < outboundFlight.size(); ++i)
        {
            writeMessage((Message)outboundFlight.elementAt(i));
        }

        resendMillis = backOff(resendMillis);
        scheduleResend();
    }

    private Message updateHandshakeMessagesDigest(Message message)
            throws IOException
    {
        short msg_type = message.getType();
        switch (msg_type)
        {
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
        case HandshakeType.new_session_ticket:
            break;

        default:
        {
            byte[] body = message.getBody();
            byte[] buf = new byte[MESSAGE_HEADER_LENGTH];
            TlsUtils.writeUint8(msg_type, buf, 0);
            TlsUtils.writeUint24(body.length, buf, 1);
            TlsUtils.writeUint16(message.getSeq(), buf, 4);
            TlsUtils.writeUint24(0, buf, 6);
            TlsUtils.writeUint24(body.length, buf, 9);
            handshakeHash.update(buf, 0, buf.length);
            handshakeHash.update(body, 0, body.length);
        }
        }

        return message;
    }

    private void writeMessage(Message message)
            throws IOException
    {
        int sendLimit = transport.getSendLimit();
        int fragmentLimit = sendLimit - MESSAGE_HEADER_LENGTH;

        // TODO Support a higher minimum fragment size?
        if (fragmentLimit < 1)
        {
            // TODO Should we be throwing an exception here?
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        int length = message.getBody().length;

        // NOTE: Must still send a fragment if body is empty
        int fragment_offset = 0;
        do
        {
            int fragment_length = Math.min(length - fragment_offset, fragmentLimit);
            writeHandshakeFragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        }
        while (fragment_offset < length);
    }

    private void writeHandshakeFragment(Message message, int fragment_offset, int fragment_length)
            throws IOException
    {
        RecordLayerBuffer fragment = new RecordLayerBuffer(MESSAGE_HEADER_LENGTH + fragment_length);
        TlsUtils.writeUint8(message.getType(), fragment);
        TlsUtils.writeUint24(message.getBody().length, fragment);
        TlsUtils.writeUint16(message.getSeq(), fragment);
        TlsUtils.writeUint24(fragment_offset, fragment);
        TlsUtils.writeUint24(fragment_length, fragment);
        fragment.write(message.getBody(), fragment_offset, fragment_length);

        fragment.sendToRecordLayer(transport);
    }

    private static boolean checkAll(Hashtable inboundFlight)
    {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements())
        {
            if (((DTLSReassembler)e.nextElement()).getBodyIfComplete() == null)
            {
                return false;
            }
        }
        return true;
    }

    private static void resetAll(Hashtable inboundFlight)
    {
        Enumeration e = inboundFlight.elements();
        while (e.hasMoreElements())
        {
            ((DTLSReassembler)e.nextElement()).reset();
        }
    }

    static class Message
    {
        private final int message_seq;
        private final short msg_type;
        private final byte[] body;

        private Message(int message_seq, short msg_type, byte[] body)
        {
            this.message_seq = message_seq;
            this.msg_type = msg_type;
            this.body = body;
        }

        public int getSeq()
        {
            return message_seq;
        }

        public short getType()
        {
            return msg_type;
        }

        public byte[] getBody()
        {
            return body;
        }
    }

    static class RecordLayerBuffer extends ByteArrayOutputStream
    {
        RecordLayerBuffer(int size)
        {
            super(size);
        }

        void sendToRecordLayer(AsyncDTLSRecordLayer recordLayer) throws IOException
        {
            recordLayer.send(buf, 0, count);
            buf = null;
        }
    }
}
