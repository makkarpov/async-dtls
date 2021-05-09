package mx.mk.asyncdtls;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256;
import static org.bouncycastle.asn1.x9.X9ObjectIdentifiers.ecdsa_with_SHA256;

public class Utils {
    public static final int MTU = 1432;

    public static class CertificateResult {
        public final X509CertificateHolder certificate;
        public final AsymmetricKeyParameter privateKey;

        public CertificateResult(X509CertificateHolder certificate, AsymmetricKeyParameter privateKey) {
            this.certificate = certificate;
            this.privateKey = privateKey;
        }

        public String fingerprint() {
            try {
                return Utils.fingerprint(certificate.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException("Cannot encode certificate", e);
            }
        }

        public TlsCredentialedSigner toCredentials(BcTlsCrypto crypto, TlsContext context) throws IOException {
            return new BcDefaultTlsCredentialedSigner(
                    new TlsCryptoParameters(context),
                    crypto,
                    privateKey,
                    new Certificate(new TlsCertificate[]{
                            new BcTlsCertificate(crypto, certificate.getEncoded())
                    }),
                    new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)
            );
        }
    }

    public static CertificateResult generateCertificate() throws Exception {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(
                    new ECNamedDomainParameters(SECObjectIdentifiers.secp256r1, NISTNamedCurves.getByName("P-256")),
                    random
            ));

            AsymmetricCipherKeyPair key = generator.generateKeyPair();

            BigInteger serial = new BigInteger(128, random);
            Instant notBefore = Instant.now().minus(10, ChronoUnit.MINUTES);
            Instant notAfter = notBefore.plus(365, ChronoUnit.DAYS);

            X500Name name = new X500NameBuilder()
                    .addRDN(BCStyle.CN, "Test Certificate")
                    .build();

            ContentSigner signer = new BcECContentSignerBuilder(new AlgorithmIdentifier(ecdsa_with_SHA256),
                    new AlgorithmIdentifier(id_sha256))
                    .setSecureRandom(random)
                    .build(key.getPrivate());

            X509CertificateHolder certificate = new BcX509v3CertificateBuilder(name, serial, Date.from(notBefore),
                    Date.from(notAfter), name, key.getPublic()).build(signer);

            return new CertificateResult(certificate, key.getPrivate());
        } catch (Exception e) {
            throw new RuntimeException("Cannot generate certificate", e);
        }
    }

    public static String hexDump(byte[] data) {
        StringBuilder r = new StringBuilder();
        for (byte b: data) {
            r.append(String.format("%02X", b & 0xFF));
        }
        return r.toString();
    }

    public static String fingerprint(byte[] data) {
        try {
            return hexDump(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new RuntimeException("Cannot hash data", e);
        }
    }

    public static void printContext(TlsContext context) {
        SessionParameters sessionParameters = context.getSession().exportSessionParameters();

        String cipherSuite = String.format("0x%04X", sessionParameters.getCipherSuite());
        try {
            for (Field f : CipherSuite.class.getFields()) {
                if (f.getInt(null) == sessionParameters.getCipherSuite()) {
                    cipherSuite = String.format("%s (%s)", f.getName(), cipherSuite);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String peerCertificate = "<none>";
        if (sessionParameters.getPeerCertificate() != null && !sessionParameters.getPeerCertificate().isEmpty()) {
            try {
                byte[] encoded = sessionParameters.getPeerCertificate().getCertificateAt(0).getEncoded();
                peerCertificate = fingerprint(encoded);
            } catch (Exception e) {
                e.printStackTrace();
                peerCertificate = "<error>";
            }
        }

        System.out.println("Handshake successful:");
        System.out.println("  Master secret:    " + hexDump(sessionParameters.getMasterSecret().extract()));
        System.out.println("  Cipher suite:     " + cipherSuite);
        System.out.println("  Peer certificate: " + peerCertificate);
    }

    public static String printMessage(byte[] message, int length) {
        return new String(message, 0, length, StandardCharsets.UTF_8).replaceAll("\n", "\\\\n");
    }
}
