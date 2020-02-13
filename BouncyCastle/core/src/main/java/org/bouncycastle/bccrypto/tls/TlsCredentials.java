package org.bouncycastle.bccrypto.tls;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsCredentials
{
    Certificate getCertificate();
}
