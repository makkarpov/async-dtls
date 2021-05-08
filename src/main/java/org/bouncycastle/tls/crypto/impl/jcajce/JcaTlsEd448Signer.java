package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.SignatureAlgorithm;

import java.security.PrivateKey;

public class JcaTlsEd448Signer
    extends JcaTlsEdDSASigner
{
    public JcaTlsEd448Signer(JcaTlsCrypto crypto, PrivateKey privateKey)
    {
        super(crypto, privateKey, SignatureAlgorithm.ed448, "Ed448");
    }
}
