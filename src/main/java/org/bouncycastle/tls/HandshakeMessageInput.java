package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsHash;

import java.io.ByteArrayInputStream;

class HandshakeMessageInput
    extends ByteArrayInputStream
{
    HandshakeMessageInput(byte[] buf, int offset, int length)
    {
        super(buf, offset, length);
    }

    public boolean markSupported()
    {
        return false;
    }

    public void mark(int readAheadLimit)
    {
        throw new UnsupportedOperationException();
    }

    void updateHash(TlsHash hash)
    {
        hash.update(buf, mark, count - mark);
    }
}
