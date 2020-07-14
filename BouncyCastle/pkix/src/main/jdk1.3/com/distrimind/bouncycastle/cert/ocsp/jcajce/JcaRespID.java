package com.distrimind.bouncycastle.cert.ocsp.jcajce;

import java.security.PublicKey;

import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.ocsp.OCSPException;
import com.distrimind.bouncycastle.cert.ocsp.RespID;
import com.distrimind.bouncycastle.operator.DigestCalculator;

public class JcaRespID
    extends RespID
{
    public JcaRespID(PublicKey pubKey, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), digCalc);
    }
}
