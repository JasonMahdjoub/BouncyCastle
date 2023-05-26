package com.distrimind.bouncycastle.cert.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.cert.X509v1CertificateBuilder;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

/**
 * JCA helper class to allow BC lightweight objects to be used in the construction of a Version 1 certificate.
 */
public class BcX509v1CertificateBuilder
    extends X509v1CertificateBuilder
{
    /**
     * Initialise the builder using an AsymmetricKeyParameter.
     *
     * @param issuer X500Name representing the issuer of this certificate.
     * @param serial the serial number for the certificate.
     * @param notBefore date before which the certificate is not valid.
     * @param notAfter date after which the certificate is not valid.
     * @param subject X500Name representing the subject of this certificate.
     * @param publicKey the public key to be associated with the certificate.
     */
    public BcX509v1CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, AsymmetricKeyParameter publicKey)
        throws IOException
    {
        super(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey));
    }
}
