package com.distrimind.bouncycastle.oer.its.etsi102941.basetypes;

import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * CertificateFormat::= INTEGER {
 * ts103097v131 (1)
 * }(1..255)
 */
public class CertificateFormat
    extends ASN1Object
{
    private final int format;

    public CertificateFormat(int format)
    {
        this.format = format;
    }

    public CertificateFormat(BigInteger format)
    {
        this.format = BigIntegers.intValueExact(format);
    }

    private CertificateFormat(ASN1Integer format)
    {
        this(format.getValue());
    }

    public int getFormat()
    {
        return format;
    }

    public static CertificateFormat getInstance(Object o)
    {
        if (o instanceof CertificateFormat)
        {
            return (CertificateFormat)o;
        }
        if (o != null)
        {
            return new CertificateFormat(ASN1Integer.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(format);
    }
}
