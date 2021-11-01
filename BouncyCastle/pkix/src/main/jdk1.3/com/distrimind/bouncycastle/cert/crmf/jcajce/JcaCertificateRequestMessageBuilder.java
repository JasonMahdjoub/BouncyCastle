package com.distrimind.bouncycastle.cert.crmf.jcajce;

import java.math.BigInteger;
import java.security.PublicKey;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;

public class JcaCertificateRequestMessageBuilder
    extends CertificateRequestMessageBuilder
{
    public JcaCertificateRequestMessageBuilder(BigInteger certReqId)
    {
        super(certReqId);
    }

    public JcaCertificateRequestMessageBuilder setPublicKey(PublicKey publicKey)
    {
        setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));

        return this;
    }
}
