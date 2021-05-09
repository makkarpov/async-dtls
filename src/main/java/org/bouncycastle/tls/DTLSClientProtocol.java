package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

public class DTLSClientProtocol
    extends DTLSProtocol
{
    public DTLSClientProtocol()
    {
        super();
    }

    public DTLSTransport connect(TlsClient client, DatagramTransport transport)
        throws IOException
    {
        if (client == null)
        {
            throw new IllegalArgumentException("'client' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        DTLSTransport ret = new DTLSTransport(transport);
        ret.setProtocol(async(client, ret.getTimer(), ret.getTransport()));
        ret.completeHandshake();
        return ret;
    }

    public DTLSAsyncProtocol async(TlsClient client, TlsTimer timer, DTLSAsyncTransport transport) throws IOException {
        DTLSAsyncClientHandshake handshake = new DTLSAsyncClientHandshake(client, timer, transport);
        return new DTLSAsyncProtocol(handshake, transport);
    }
}
