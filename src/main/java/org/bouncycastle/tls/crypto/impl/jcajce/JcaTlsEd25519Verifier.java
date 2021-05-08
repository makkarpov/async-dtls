package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.SignatureAlgorithm;

import java.security.PublicKey;

public class JcaTlsEd25519Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd25519Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed25519, "Ed25519");
    }
}
