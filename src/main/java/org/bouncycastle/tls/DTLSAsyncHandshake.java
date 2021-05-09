package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Base class for interaction handshake state machines
 */
abstract class DTLSAsyncHandshake {
    private DTLSReliableHandshake.Message receivedMessage;
    protected DTLSReliableHandshake handshake;

    /**
     * Push received datagram for processing. Processing result will be reported as transport events.
     *
     * @param data   Received datagram contents
     * @param offset Datagram offset
     * @param length Datagram length
     */
    abstract void pushReceivedDatagram(byte[] data, int offset, int length) throws IOException;

    /**
     * Checks for handshake completion. Used to terminate message loop in synchronous API's and switch to data flow in
     * asynchronous.
     *
     * @return Whether handshake was completed by last message
     */
    abstract boolean handshakeCompleted();

    /**
     * @return DTLS record layer
     */
    abstract DTLSRecordLayer recordLayer();

    /**
     * @return TLS context object
     */
    abstract TlsContext context();

    /**
     * Aborts the handshake, cancelling any scheduled timers
     */
    abstract void abort(short alertDescription);

    abstract void clear();

    protected DTLSReliableHandshake.Message receiveMessage() throws IOException {
        if (receivedMessage == null) {
            receivedMessage = handshake.receiveMessage();
        }

        return receivedMessage;
    }

    protected byte[] receiveMessageBody(short msg_type) throws IOException {
        DTLSReliableHandshake.Message message = receiveMessage();
        if (message == null) {
            return null;
        }

        if (message.getType() != msg_type) {
            throw new TlsFatalAlert(AlertDescription.unexpected_message, "expected " + msg_type + ", got " +
                    message.getType());
        }

        return message.getBody();
    }

    protected void consumeMessage() {
        receivedMessage = null;
    }

    protected void processFinished(byte[] body, byte[] expected_verify_data)
            throws IOException
    {
        ByteArrayInputStream buf = new ByteArrayInputStream(body);

        byte[] verify_data = TlsUtils.readFully(expected_verify_data.length, buf);

        TlsProtocol.assertEmpty(buf);

        if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    protected static void applyMaxFragmentLengthExtension(DTLSRecordLayer recordLayer, short maxFragmentLength)
            throws IOException
    {
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            int plainTextLimit = 1 << (8 + maxFragmentLength);
            recordLayer.setPlaintextLimit(plainTextLimit);
        }
    }

    protected static short evaluateMaxFragmentLengthExtension(boolean resumedSession, Hashtable clientExtensions,
                                                              Hashtable serverExtensions, short alertDescription) throws IOException
    {
        short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength)
                    || (!resumedSession && maxFragmentLength != TlsExtensionsUtils
                    .getMaxFragmentLengthExtension(clientExtensions)))
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
        return maxFragmentLength;
    }

    protected static byte[] generateCertificate(TlsContext context, Certificate certificate, OutputStream endPointHash)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        certificate.encode(context, buf, endPointHash);
        return buf.toByteArray();
    }

    protected static byte[] generateSupplementalData(Vector supplementalData)
            throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsProtocol.writeSupplementalData(buf, supplementalData);
        return buf.toByteArray();
    }

    protected static void sendCertificateMessage(TlsContext context, DTLSReliableHandshake handshake,
                                                 Certificate certificate, OutputStream endPointHash) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        if (null != securityParameters.getLocalCertificate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (null == certificate)
        {
            certificate = Certificate.EMPTY_CHAIN;
        }

        byte[] certificateBody = generateCertificate(context, certificate, endPointHash);
        handshake.sendMessage(HandshakeType.certificate, certificateBody);

        securityParameters.localCertificate = certificate;
    }

    protected static int validateSelectedCipherSuite(int selectedCipherSuite, short alertDescription)
            throws IOException
    {
        switch (TlsUtils.getEncryptionAlgorithm(selectedCipherSuite))
        {
        case EncryptionAlgorithm.RC4_40:
        case EncryptionAlgorithm.RC4_128:
        case -1:
            throw new TlsFatalAlert(alertDescription);
        default:
            return selectedCipherSuite;
        }
    }
}
