package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Operator supporting the generation of RSASSA-PSS signatures.
 */
public class JcaTlsRSAPSSSigner
    implements TlsSigner
{
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final short signatureAlgorithm;

    public JcaTlsRSAPSSSigner(JcaTlsCrypto crypto, PrivateKey privateKey, short signatureAlgorithm)
    {
        if (null == crypto)
        {
            throw new NullPointerException("crypto");
        }
        if (null == privateKey)
        {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureAlgorithm.isRSAPSS(signatureAlgorithm))
        {
            throw new IllegalArgumentException("signatureAlgorithm");
        }

        this.crypto = crypto;
        this.privateKey = privateKey;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) throws IOException
    {
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

        return crypto.createStreamSigner(sigName, pssSpec, privateKey, true);
    }
}
