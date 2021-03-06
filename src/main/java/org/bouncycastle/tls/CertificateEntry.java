package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCertificate;

import java.util.Hashtable;

public class CertificateEntry
{
    protected final TlsCertificate certificate;
    protected final Hashtable extensions;

    public CertificateEntry(TlsCertificate certificate, Hashtable extensions)
    {
        if (null == certificate)
        {
            throw new NullPointerException("'certificate' cannot be null");
        }

        this.certificate = certificate;
        this.extensions = extensions;
    }

    public TlsCertificate getCertificate()
    {
        return certificate;
    }

    public Hashtable getExtensions()
    {
        return extensions;
    }
}
