package com.distrimind.bouncycastle.oer.its.ieee1609dot2;

import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * PreSharedKeyRecipientInfo ::= HashedId8
 */
public class PreSharedKeyRecipientInfo
    extends HashedId8
{
    public PreSharedKeyRecipientInfo(byte[] string)
    {
        super(string);
    }


    public static PreSharedKeyRecipientInfo getInstance(Object object)
    {
        if (object instanceof PreSharedKeyRecipientInfo)
        {
            return (PreSharedKeyRecipientInfo)object;
        }

        if (object != null)
        {
            if (object instanceof HashedId)
            {
                return new PreSharedKeyRecipientInfo(((HashedId)object).getHashBytes());
            }

            return new PreSharedKeyRecipientInfo(ASN1OctetString.getInstance(object).getOctets());
        }

        return null;
    }
}
