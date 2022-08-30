package org.bouncycastle.cert.ocsp;

import com.distrimind.bouncycastle.asn1.ocsp.Request;
import com.distrimind.bouncycastle.asn1.x509.Extensions;

public class Req
{
    private Request req;

    public Req(
        Request req)
    {
        this.req = req;
    }

    public CertificateID getCertID()
    {
        return new CertificateID(req.getReqCert());
    }

    public Extensions getSingleRequestExtensions()
    {
        return req.getSingleRequestExtensions();
    }
}
