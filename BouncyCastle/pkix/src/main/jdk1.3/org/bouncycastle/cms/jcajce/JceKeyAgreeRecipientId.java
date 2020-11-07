package com.distrimind.bouncycastle.cms.jcajce;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.distrimind.bouncycastle.jce.PrincipalUtil;
import com.distrimind.bouncycastle.jce.X509Principal;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.cms.KeyAgreeRecipientId;

public class JceKeyAgreeRecipientId
    extends KeyAgreeRecipientId
{
    public JceKeyAgreeRecipientId(X509Certificate certificate)
    {
        super(X500Name.getInstance(extractIssuer(certificate)), certificate.getSerialNumber());
    }

    private static X509Principal extractIssuer(X509Certificate certificate)
    {
        try
        {
            return PrincipalUtil.getIssuerX509Principal(certificate);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException("can't extract issuer");
        }
    }
}
