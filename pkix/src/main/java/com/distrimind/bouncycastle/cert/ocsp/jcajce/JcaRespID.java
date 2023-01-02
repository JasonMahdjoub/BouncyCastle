package com.distrimind.bouncycastle.cert.ocsp.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.operator.DigestCalculator;
import com.distrimind.bouncycastle.cert.ocsp.OCSPException;
import com.distrimind.bouncycastle.cert.ocsp.RespID;

public class JcaRespID
    extends RespID
{
    public JcaRespID(X500Principal name)
    {
        super(X500Name.getInstance(name.getEncoded()));
    }

    public JcaRespID(PublicKey pubKey, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), digCalc);
    }
}
