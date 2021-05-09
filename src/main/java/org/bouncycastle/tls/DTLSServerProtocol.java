package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

public class DTLSServerProtocol
    extends DTLSProtocol
{
    protected boolean verifyRequests = true;

    public DTLSServerProtocol()
    {
        super();
    }

    public boolean getVerifyRequests()
    {
        return verifyRequests;
    }

    public void setVerifyRequests(boolean verifyRequests)
    {
        this.verifyRequests = verifyRequests;
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport)
        throws IOException
    {
        return accept(server, transport, null);
    }

    public DTLSTransport accept(TlsServer server, DatagramTransport transport, DTLSRequest request)
        throws IOException
    {
        if (server == null)
        {
            throw new IllegalArgumentException("'server' cannot be null");
        }
        if (transport == null)
        {
            throw new IllegalArgumentException("'transport' cannot be null");
        }

        DTLSTransport ret = new DTLSTransport(transport);
        ret.setProtocol(async(server, ret.getTimer(), ret.getTransport(), request));
        ret.completeHandshake();
        return ret;
    }

    public DTLSAsyncProtocol async(TlsServer server, TlsTimer timer, DTLSAsyncTransport transport) throws IOException {
        return async(server, timer, transport, null);
    }

    public DTLSAsyncProtocol async(TlsServer server, TlsTimer timer, DTLSAsyncTransport transport,
                                   DTLSRequest request) throws IOException
    {
        DTLSAsyncHandshake handshake = new DTLSAsyncServerHandshake(server, timer, transport, request);
        return new DTLSAsyncProtocol(handshake, transport);
    }
}
