package org.bouncycastle.bcjcajce.provider.asymmetric.x509;

import java.security.cert.CRLException;

import org.bouncycastle.bcasn1.x509.CertificateList;
import org.bouncycastle.bcjcajce.util.JcaJceHelper;

class X509CRLInternal extends X509CRLImpl
{
    private final byte[] encoding;

    X509CRLInternal(JcaJceHelper bcHelper, CertificateList c, String sigAlgName, byte[] sigAlgParams, boolean isIndirect,
        byte[] encoding)
    {
        super(bcHelper, c, sigAlgName, sigAlgParams, isIndirect);

        this.encoding = encoding;
    }

    public byte[] getEncoded() throws CRLException
    {
        if (null == encoding)
        {
            throw new CRLException();
        }

        return encoding;
    }
}
