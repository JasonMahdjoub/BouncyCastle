package com.distrimind.bouncycastle.cert.ocsp.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import com.distrimind.bouncycastle.operator.DigestCalculator;
import com.distrimind.bouncycastle.cert.ocsp.OCSPException;

public class JcaBasicOCSPRespBuilder
    extends BasicOCSPRespBuilder
{
    public JcaBasicOCSPRespBuilder(X500Principal principal)
    {
        super(new JcaRespID(principal));
    }

    public JcaBasicOCSPRespBuilder(PublicKey key, DigestCalculator digCalc)
        throws OCSPException
    {
        super(SubjectPublicKeyInfo.getInstance(key.getEncoded()), digCalc);
    }
}
