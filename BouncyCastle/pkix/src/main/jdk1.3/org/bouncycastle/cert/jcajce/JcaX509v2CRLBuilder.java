package org.bouncycastle.cert.jcajce;

import java.util.Date;

import org.bouncycastle.bcasn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;

public class JcaX509v2CRLBuilder
    extends X509v2CRLBuilder
{
    public JcaX509v2CRLBuilder(X500Name issuer, Date now)
    {
        super(issuer, now);
    }
}
