package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * <pre>
 *     LinkageValue ::= OCTET STRING (SIZE(9))
 * </pre>
 */
public class LinkageValue
    extends ASN1Object
{
    private final byte[] value;

    private LinkageValue(ASN1OctetString octs)
    {
        this.value = Arrays.clone(Utils.octetStringFixed(octs.getOctets(), 9));
    }

    public static LinkageValue getInstance(Object src)
    {
        if (src instanceof LinkageValue)
        {
            return (LinkageValue)src;
        }
        else if (src != null)
        {
            return new LinkageValue(ASN1OctetString.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(Arrays.clone(value));
    }
}
