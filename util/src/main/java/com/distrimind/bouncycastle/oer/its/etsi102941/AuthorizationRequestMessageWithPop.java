package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class AuthorizationRequestMessageWithPop
    extends EtsiTs103097DataEncryptedUnicast
{

    public AuthorizationRequestMessageWithPop(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationRequestMessageWithPop(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationRequestMessageWithPop getInstance(Object o)
    {
        if (o instanceof AuthorizationRequestMessageWithPop)
        {
            return (AuthorizationRequestMessageWithPop)o;
        }
        if (o != null)
        {
            return new AuthorizationRequestMessageWithPop(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
