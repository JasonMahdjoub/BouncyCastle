package com.distrimind.bouncycastle.cert.crmf;

import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cms.CMSEnvelopedData;
import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.cmp.CertOrEncCert;
import com.distrimind.bouncycastle.asn1.cmp.CertResponse;
import com.distrimind.bouncycastle.asn1.cmp.CertifiedKeyPair;
import com.distrimind.bouncycastle.asn1.cmp.PKIStatusInfo;
import com.distrimind.bouncycastle.asn1.cms.EnvelopedData;
import com.distrimind.bouncycastle.asn1.crmf.EncryptedKey;

/**
 * Builder for CertificateResponse objects (the CertResponse CRMF equivalent).
 */
public class CertificateResponseBuilder
{
    private CertifiedKeyPair certKeyPair;
    private ASN1Integer certReqId;
    private PKIStatusInfo statusInfo;
    private DEROctetString rspInfo;

    /**
     * Base constructor.
     *
     * @param certReqId the request ID for the response.
     * @param statusInfo the status info to associate with the response.
     */
    public CertificateResponseBuilder(ASN1Integer certReqId, PKIStatusInfo statusInfo)
    {
        this.certReqId = certReqId;
        this.statusInfo = statusInfo;
    }

    /**
     * Specify the certificate to assign to this response (in plaintext).
     *
     * @param certificate the X.509 PK certificate to include.
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(X509CertificateHolder certificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(new CMPCertificate(certificate.toASN1Structure())));

        return this;
    }

    /**
     * Specify the certificate to assign to this response (in plaintext).
     *
     * @param certificate the X.509 PK certificate to include.
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(CMPCertificate certificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(certificate));

        return this;
    }

    /**
     * Specify the encrypted certificate to assign to this response (in plaintext).
     *
     * @param encryptedCertificate an encrypted
     * @return the current builder.
     */
    public CertificateResponseBuilder withCertificate(CMSEnvelopedData encryptedCertificate)
    {
        if (certKeyPair != null)
        {
            throw new IllegalStateException("certificate in response already set");
        }

        this.certKeyPair = new CertifiedKeyPair(
            new CertOrEncCert(
                new EncryptedKey(EnvelopedData.getInstance(encryptedCertificate.toASN1Structure().getContent()))));

        return this;
    }

    /**
     * Specify the response info field on the response.
     *
     * @param responseInfo a response info string.
     * @return the current builder.
     */
    public CertificateResponseBuilder withResponseInfo(byte[] responseInfo)
    {
        if (rspInfo != null)
        {
            throw new IllegalStateException("response info already set");
        }

        this.rspInfo = new DEROctetString(responseInfo);

        return this;
    }

    public CertificateResponse build()
    {
        return new CertificateResponse(new CertResponse(certReqId, statusInfo, certKeyPair, rspInfo));
    }
}