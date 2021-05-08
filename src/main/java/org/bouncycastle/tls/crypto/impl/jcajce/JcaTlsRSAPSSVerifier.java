package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Operator supporting the verification of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSVerifier
    implements TlsVerifier
{
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final short signatureAlgorithm;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto crypto, PublicKey publicKey, short signatureAlgorithm)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == publicKey)
        {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.crypto = crypto;
        this.publicKey = publicKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean verifyRawSignature(DigitallySigned signature, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamVerifier getStreamVerifier(DigitallySigned signature) throws IOException
    {
        SignatureAndHashAlgorithm algorithm = signature.getAlgorithm();
        if (algorithm == null
            || algorithm.getSignature() != signatureAlgorithm
            || algorithm.getHash() != HashAlgorithm.Intrinsic)
        {
            throw new IllegalStateException("Invalid algorithm: " + algorithm);
        }

        int cryptoHashAlgorithm = TlsCryptoUtils
            .getHash(SignatureAlgorithm.getIntrinsicHashAlgorithm(signatureAlgorithm));
        String digestName = crypto.getDigestName(cryptoHashAlgorithm);
        String sigName = RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1";

        // NOTE: We explicitly set them even though they should be the defaults, because providers vary
        AlgorithmParameterSpec pssSpec = RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName,
            crypto.getHelper());

        return crypto.createStreamVerifier(sigName, pssSpec, signature.getSignature(), publicKey);
    }
}
