package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

abstract class AsyncDTLSHandshake {
    abstract AsyncDTLSRecordLayer getRecordLayer();

    abstract boolean handshakeCompleted();

    abstract void pushReceivedData(byte[] data, int offset, int length);

    protected static void applyMaxFragmentLengthExtension(AsyncDTLSRecordLayer recordLayer, short maxFragmentLength)
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

    protected static void sendCertificateMessage(TlsContext context, AsyncDTLSReliableHandshake handshake,
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

        byte[] certificateBody = DTLSProtocol.generateCertificate(context, certificate, endPointHash);
        handshake.sendMessage(HandshakeType.certificate, certificateBody);

        securityParameters.localCertificate = certificate;
    }
}
