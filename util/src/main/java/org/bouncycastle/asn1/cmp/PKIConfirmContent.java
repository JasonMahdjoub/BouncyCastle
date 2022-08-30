package org.bouncycastle.asn1.cmp;

import com.distrimind.bouncycastle.asn1.ASN1Null;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DERNull;

public class PKIConfirmContent
    extends ASN1Object
{
    private final ASN1Null val;

    private PKIConfirmContent(ASN1Null val)
    {
        this.val = val;
    }

    public PKIConfirmContent()
    {
        val = DERNull.INSTANCE;
    }

    public static PKIConfirmContent getInstance(Object o)
    {
        if (o == null || o instanceof PKIConfirmContent)
        {
            return (PKIConfirmContent)o;
        }

        if (o instanceof ASN1Null)
        {
            return new PKIConfirmContent((ASN1Null)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    /**
     * <pre>
     * PKIConfirmContent ::= NULL
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return val;
    }
}
