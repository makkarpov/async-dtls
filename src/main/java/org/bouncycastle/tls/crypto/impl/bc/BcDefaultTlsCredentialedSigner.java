package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.params.*;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

import java.io.IOException;

/**
 * Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.
 */
public class BcDefaultTlsCredentialedSigner
    extends DefaultTlsCredentialedSigner
{
    private static BcTlsCertificate getEndEntity(BcTlsCrypto crypto, Certificate certificate) throws IOException
    {
        if (certificate == null || certificate.isEmpty())
        {
            throw new IllegalArgumentException("No certificate");
        }

        return BcTlsCertificate.convert(crypto, certificate.getCertificateAt(0));
    }

    private static TlsSigner makeSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate,
        SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        TlsSigner signer;
        if (privateKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters privKeyRSA = (RSAKeyParameters)privateKey;

            if (signatureAndHashAlgorithm != null)
            {
                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
                switch (signatureAlgorithm)
                {
                case SignatureAlgorithm.rsa_pss_pss_sha256:
                case SignatureAlgorithm.rsa_pss_pss_sha384:
                case SignatureAlgorithm.rsa_pss_pss_sha512:
                case SignatureAlgorithm.rsa_pss_rsae_sha256:
                case SignatureAlgorithm.rsa_pss_rsae_sha384:
                case SignatureAlgorithm.rsa_pss_rsae_sha512:
                    return new BcTlsRSAPSSSigner(crypto, privKeyRSA, signatureAlgorithm);
                }
            }

            RSAKeyParameters pubKeyRSA;
            try
            {
                pubKeyRSA = getEndEntity(crypto, certificate).getPubKeyRSA();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }

            signer = new BcTlsRSASigner(crypto, privKeyRSA, pubKeyRSA);
        }
        else if (privateKey instanceof DSAPrivateKeyParameters)
        {
            signer = new BcTlsDSASigner(crypto, (DSAPrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            ECPrivateKeyParameters privKeyEC = (ECPrivateKeyParameters)privateKey;

            // TODO[RFC 8998]
//            if (signatureAndHashAlgorithm != null)
//            {
//                short signatureAlgorithm = signatureAndHashAlgorithm.getSignature();
//                switch (signatureAlgorithm)
//                {
//                case SignatureAlgorithm.sm2:
//                    return new BcTlsSM2Signer(crypto, privKeyEC, Strings.toByteArray("TLSv1.3+GM+Cipher+Suite"));
//                }
//            }

            signer = new BcTlsECDSASigner(crypto, privKeyEC);
        }
        else if (privateKey instanceof Ed25519PrivateKeyParameters)
        {
            signer = new BcTlsEd25519Signer(crypto, (Ed25519PrivateKeyParameters)privateKey);
        }
        else if (privateKey instanceof Ed448PrivateKeyParameters)
        {
            signer = new BcTlsEd448Signer(crypto, (Ed448PrivateKeyParameters)privateKey);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
        }

        return signer;
    }

    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
        AsymmetricKeyParameter privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        super(cryptoParams, makeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
            signatureAndHashAlgorithm);
    }
}
