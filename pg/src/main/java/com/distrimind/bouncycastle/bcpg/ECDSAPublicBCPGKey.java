package com.distrimind.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.math.ec.ECPoint;

/**
 * base class for an ECDSA Public Key.
 */
public class ECDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected ECDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
    }

    public ECDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public ECDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
        throws IOException
    {
        super(oid, encodedPoint);
    }

}
