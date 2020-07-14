package com.distrimind.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CertificateEncodingException;

import com.distrimind.bouncycastle.asn1.x509.BasicConstraints;
import com.distrimind.bouncycastle.asn1.x509.Certificate;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;

class X509CertificateInternal extends X509CertificateImpl
{
    private final byte[] encoding;

    X509CertificateInternal(JcaJceHelper bcHelper, Certificate c,
        BasicConstraints basicConstraints, boolean[] keyUsage, String sigAlgName, byte[] sigAlgParams, byte[] encoding)
    {
        super(bcHelper, c, basicConstraints, keyUsage, sigAlgName, sigAlgParams);

        this.encoding = encoding;
    }

    public byte[] getEncoded() throws CertificateEncodingException
    {
        if (null == encoding)
        {
            throw new CertificateEncodingException();
        }

        return encoding;
    }
}
