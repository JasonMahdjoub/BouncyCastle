package com.distrimind.bouncycastle.tls.crypto;

import java.io.IOException;
import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.tls.ConnectionEnd;
import com.distrimind.bouncycastle.tls.KeyExchangeAlgorithm;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

/**
 * Interface providing the functional representation of a single X.509 certificate.
 */
public interface TlsCertificate
{
    /**
     * @param signatureAlgorithm
     *            {@link SignatureAlgorithm}
     */
    TlsVerifier createVerifier(short signatureAlgorithm) throws IOException;

    byte[] getEncoded() throws IOException;

    byte[] getExtension(ASN1ObjectIdentifier extensionOID) throws IOException;

    BigInteger getSerialNumber();

    /**
     * @return the OID of this certificate's 'signatureAlgorithm', as a String.
     */
    String getSigAlgOID();

    ASN1Encodable getSigAlgParams() throws IOException;

    /**
     * @return {@link SignatureAlgorithm}
     */
    short getLegacySignatureAlgorithm() throws IOException;

    /**
     * @param signatureAlgorithm {@link SignatureAlgorithm}
     * @return true if (and only if) this certificate can be used to verify the given signature algorithm. 
     */
    boolean supportsSignatureAlgorithm(short signatureAlgorithm) throws IOException;

    boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) throws IOException;

    /**
     * @param connectionEnd
     *            {@link ConnectionEnd}
     * @param keyExchangeAlgorithm
     *            {@link KeyExchangeAlgorithm}
     */
    // TODO[tls-ops] This is expected to be only transitional and eventually redundant
    TlsCertificate useInRole(int connectionEnd, int keyExchangeAlgorithm) throws IOException;
}
