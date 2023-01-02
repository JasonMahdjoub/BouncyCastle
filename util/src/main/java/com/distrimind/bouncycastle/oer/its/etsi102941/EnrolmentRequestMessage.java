package com.distrimind.bouncycastle.oer.its.etsi102941;

import com.distrimind.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.distrimind.bouncycastle.asn1.ASN1Sequence;

public class EnrolmentRequestMessage
    extends EtsiTs103097DataSignedAndEncryptedUnicast
{

    public EnrolmentRequestMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EnrolmentRequestMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static EnrolmentRequestMessage getInstance(Object o)
    {
        if (o instanceof EnrolmentRequestMessage)
        {
            return (EnrolmentRequestMessage)o;
        }
        if (o != null)
        {
            return new EnrolmentRequestMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}