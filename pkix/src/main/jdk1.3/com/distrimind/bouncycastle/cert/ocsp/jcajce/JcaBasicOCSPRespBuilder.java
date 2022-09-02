package com.distrimind.bouncycastle.cert.ocsp.jcajce;

import java.security.PublicKey;

import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import com.distrimind.bouncycastle.cert.ocsp.OCSPException;
import com.distrimind.bouncycastle.operator.DigestCalculator;

public class JcaBasicOCSPRespBuilder
    extends BasicOCSPRespBuilder
{
    public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc);
    }
}
