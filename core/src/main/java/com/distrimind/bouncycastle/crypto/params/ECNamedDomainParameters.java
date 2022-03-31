package com.distrimind.bouncycastle.crypto.params;

import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.math.ec.ECConstants;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPoint;

public class ECNamedDomainParameters
    extends ECDomainParameters
{
    private ASN1ObjectIdentifier name;

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n)
    {
        this(name, curve, G, n, ECConstants.ONE, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h)
    {
        this(name, curve, G, n, h, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed)
    {
        super(curve, G, n, h, seed);

        this.name = name;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, ECDomainParameters domainParameters)
    {
        super(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH(), domainParameters.getSeed());
        this.name = name;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name, X9ECParameters x9)
    {
        super(x9);
        this.name = name;
    }

    public ASN1ObjectIdentifier getName()
    {
        return name;
    }
}
