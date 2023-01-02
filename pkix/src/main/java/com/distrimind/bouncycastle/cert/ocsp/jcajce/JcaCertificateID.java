package com.distrimind.bouncycastle.cert.ocsp.jcajce;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import com.distrimind.bouncycastle.operator.DigestCalculator;
import com.distrimind.bouncycastle.cert.ocsp.CertificateID;
import com.distrimind.bouncycastle.cert.ocsp.OCSPException;

public class JcaCertificateID
    extends CertificateID
{
    public JcaCertificateID(DigestCalculator digestCalculator, X509Certificate issuerCert, BigInteger number)
        throws OCSPException, CertificateEncodingException
    {
        super(digestCalculator, new JcaX509CertificateHolder(issuerCert), number);
    }
}
