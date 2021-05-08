package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

import java.io.IOException;

/**
 * Base interface for a class that decrypts TLS secrets.
 */
public interface TlsCredentialedDecryptor
    extends TlsCredentials
{
    /**
     * Decrypt the passed in cipher text using the parameters available.
     *
     * @param cryptoParams the parameters to use for the decryption.
     * @param ciphertext the cipher text containing the secret.
     * @return a TlS secret.
     * @throws IOException on a parsing or decryption error.
     */
    TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException;
}
