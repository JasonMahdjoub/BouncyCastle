package com.distrimind.bouncycastle.tls;

import java.io.IOException;

import com.distrimind.bouncycastle.tls.crypto.TlsCryptoParameters;
import com.distrimind.bouncycastle.tls.crypto.TlsSecret;

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
