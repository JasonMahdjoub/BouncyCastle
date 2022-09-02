package com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;

/**
 * Psid ::= INTEGER (0..MAX)
 */
public class Psid
    extends ASN1Object
{
    private final BigInteger psid;

    public Psid(long psid)
    {
        this(BigInteger.valueOf(psid));
    }

    public Psid(BigInteger psid)
    {
        if (psid.signum() < 0)
        {
            throw new IllegalStateException("psid must be greater than zero");
        }
        this.psid = psid;

    }

    public BigInteger getPsid()
    {
        return psid;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(psid);
    }

    public static Psid getInstance(Object o)
    {
        if (o instanceof Psid)
        {
            return (Psid)o;
        }

        if (o != null)
        {
            return new Psid(ASN1Integer.getInstance(o).getValue());
        }

        return null;

    }
}
