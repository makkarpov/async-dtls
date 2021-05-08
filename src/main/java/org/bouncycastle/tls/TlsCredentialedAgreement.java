package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;

import java.io.IOException;

/**
 * Support interface for generating a secret based on the credentials sent by a TLS peer.
 */
public interface TlsCredentialedAgreement
    extends TlsCredentials
{
    /**
     * Calculate an agreed secret based on our credentials and the public key credentials of our peer.
     *
     * @param peerCertificate public key certificate of our TLS peer.
     * @return the agreed secret.
     * @throws IOException in case of an exception on generation of the secret.
     */
    TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException;
}
