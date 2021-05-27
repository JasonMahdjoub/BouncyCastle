package com.distrimind.bouncycastle.tls;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x509.X509ObjectIdentifiers;

/**
 * Object Identifiers associated with TLS extensions.
 */
public interface TlsObjectIdentifiers
{
    /**
     * RFC 7633
     */
    static final ASN1ObjectIdentifier id_pe_tlsfeature = X509ObjectIdentifiers.id_pe.branch("24");
}
