package com.distrimind.bouncycastle.cert.crmf.jcajce;

import java.io.IOException;
import java.security.Provider;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.crmf.CertReqMsg;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.crmf.CRMFException;
import com.distrimind.bouncycastle.cert.crmf.CertificateRequestMessage;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JcaCertificateRequestMessage
    extends CertificateRequestMessage
{
    private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());

    public JcaCertificateRequestMessage(byte[] certReqMsg)
    {
        this(CertReqMsg.getInstance(certReqMsg));
    }

    public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg)
    {
        this(certReqMsg.toASN1Structure());
    }

    public JcaCertificateRequestMessage(CertReqMsg certReqMsg)
    {
        super(certReqMsg);
    }

    public JcaCertificateRequestMessage setProvider(String providerName)
    {
        this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JcaCertificateRequestMessage setProvider(Provider provider)
    {
        this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public X500Principal getSubjectX500Principal()
    {
        X500Name subject = this.getCertTemplate().getSubject();

        if (subject != null)
        {
            try
            {
                return new X500Principal(subject.getEncoded(ASN1Encoding.DER));
            }
            catch (IOException e)
            {
                throw new IllegalStateException("unable to construct DER encoding of name: " + e.getMessage());
            }
        }

        return null;
    }

    public PublicKey getPublicKey()
        throws CRMFException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return helper.toPublicKey(subjectPublicKeyInfo);
        }

        return null;
    }
}
