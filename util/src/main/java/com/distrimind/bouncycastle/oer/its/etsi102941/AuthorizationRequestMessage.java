package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class AuthorizationRequestMessage
    extends EtsiTs103097DataEncryptedUnicast
{

    public AuthorizationRequestMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationRequestMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationRequestMessage getInstance(Object o)
    {
        if (o instanceof AuthorizationRequestMessage)
        {
            return (AuthorizationRequestMessage)o;
        }
        if (o != null)
        {
            return new AuthorizationRequestMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
