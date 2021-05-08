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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256;
import static org.bouncycastle.asn1.x9.X9ObjectIdentifiers.ecdsa_with_SHA256;

public class CertificateUtils {
    public static class CertificateResult {
        public final X509CertificateHolder certificate;
        public final AsymmetricKeyParameter privateKey;

        public CertificateResult(X509CertificateHolder certificate, AsymmetricKeyParameter privateKey) {
            this.certificate = certificate;
            this.privateKey = privateKey;
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
}
