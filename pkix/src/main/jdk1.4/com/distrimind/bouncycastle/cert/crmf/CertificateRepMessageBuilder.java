package com.distrimind.bouncycastle.cert.crmf;

import java.util.ArrayList;
import java.util.List;

import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.cmp.CertRepMessage;
import com.distrimind.bouncycastle.asn1.cmp.CertResponse;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;

/**
 * Builder for a CertRepMessage.
 */
public class CertificateRepMessageBuilder
{
    private final List<CertResponse> responses = new ArrayList<CertResponse>();
    private final CMPCertificate[] caCerts;

    /**
     * Base constructor which can accept 0 or more certificates representing the CA plus its chain.
     *
     * @param caCerts the CA public key and it's support certificates (optional)
     */
    public CertificateRepMessageBuilder(X509CertificateHolder[] caCerts)
    {
        this.caCerts = new CMPCertificate[caCerts.length];

        for (int i = 0; i != caCerts.length; i++)
        {
            this.caCerts[i] = new CMPCertificate(caCerts[i].toASN1Structure());
        }
    }

    public CertificateRepMessageBuilder(X509CertificateHolder caCert)
    {
        this.caCerts = new CMPCertificate[1];
        this.caCerts[0] = new CMPCertificate(caCert.toASN1Structure());
    }

    public CertificateRepMessageBuilder addCertificateResponse(CertificateResponse response)
    {
        responses.add(response.toASN1Structure());

        return this;
    }

    public CertificateRepMessage build()
    {
        CertRepMessage repMessage;
        if (caCerts.length != 0)
        {
            repMessage = new CertRepMessage(caCerts, (CertResponse[])responses.toArray(new CertResponse[0]));
        }
        else
        {
            // older versions of CertRepMessage need null if no caCerts.
            repMessage = new CertRepMessage(null, (CertResponse[])responses.toArray(new CertResponse[0]));
        }

        responses.clear();

        return new CertificateRepMessage(repMessage);
    }
}