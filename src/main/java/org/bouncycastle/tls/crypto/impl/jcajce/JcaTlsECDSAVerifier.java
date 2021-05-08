package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.SignatureAlgorithm;

import java.security.PublicKey;

/**
 * Implementation class for the verification of the raw ECDSA signature type using the JCA.
 */
public class JcaTlsECDSAVerifier
    extends JcaTlsDSSVerifier
{
    public JcaTlsECDSAVerifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ecdsa, "NoneWithECDSA");
    }
}
