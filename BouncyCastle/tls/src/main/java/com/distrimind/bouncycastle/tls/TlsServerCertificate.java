package com.distrimind.bouncycastle.tls;

/**
 * Server certificate carrier interface.
 */
public interface TlsServerCertificate
{
    Certificate getCertificate();

    CertificateStatus getCertificateStatus();
}
