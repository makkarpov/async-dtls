package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.SignatureAlgorithm;

import java.security.PublicKey;

public class JcaTlsEd448Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd448Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed448, "Ed448");
    }
}
