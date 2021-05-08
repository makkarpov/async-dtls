package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.SignatureAlgorithm;

import java.security.PrivateKey;

/**
 * Implementation class for generation of the raw ECDSA signature type using the JCA.
 */
public class JcaTlsECDSASigner
    extends JcaTlsDSSSigner
{
    public JcaTlsECDSASigner(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        super(crypto, privateKey, SignatureAlgorithm.ecdsa, "NoneWithECDSA");
    }
}
