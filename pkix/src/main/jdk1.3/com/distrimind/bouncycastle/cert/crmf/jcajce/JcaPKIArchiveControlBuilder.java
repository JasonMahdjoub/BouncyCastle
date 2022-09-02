package com.distrimind.bouncycastle.cert.crmf.jcajce;

import java.security.PrivateKey;

import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x500.X500Name;
import com.distrimind.bouncycastle.asn1.x509.GeneralName;
import com.distrimind.bouncycastle.cert.crmf.PKIArchiveControlBuilder;

public class JcaPKIArchiveControlBuilder
    extends PKIArchiveControlBuilder
{
    public JcaPKIArchiveControlBuilder(PrivateKey privateKey, X500Name name)
    {
        this(privateKey, new GeneralName(name));
    }

    public JcaPKIArchiveControlBuilder(PrivateKey privateKey, GeneralName generalName)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()), generalName);
    }
}
