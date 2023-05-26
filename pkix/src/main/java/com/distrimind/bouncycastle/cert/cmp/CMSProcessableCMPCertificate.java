package com.distrimind.bouncycastle.cert.cmp;

import java.io.IOException;
import java.io.OutputStream;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.CMSTypedData;
import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Carrier class for a CMPCertificate over CMS.
 */
public class CMSProcessableCMPCertificate
    implements CMSTypedData
{
    private final CMPCertificate cmpCert;

    public CMSProcessableCMPCertificate(X509CertificateHolder certificateHolder)
    {
        this(new CMPCertificate(certificateHolder.toASN1Structure()));
    }

    public CMSProcessableCMPCertificate(CMPCertificate cmpCertificate)
    {
        this.cmpCert = cmpCertificate;
    }

    @Override
    public void write(OutputStream out)
        throws IOException, CMSException
    {
        out.write(cmpCert.getEncoded());
    }

    @Override
    public Object getContent()
    {
        return cmpCert;
    }

    @Override
    public ASN1ObjectIdentifier getContentType()
    {
        return PKCSObjectIdentifiers.data;
    }
}
