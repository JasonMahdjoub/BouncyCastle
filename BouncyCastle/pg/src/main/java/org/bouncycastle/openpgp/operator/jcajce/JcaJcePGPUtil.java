package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcasn1.x9.ECNamedCurveTable;
import org.bouncycastle.bcasn1.x9.X9ECParameters;
import org.bouncycastle.bccrypto.ec.CustomNamedCurves;
import org.bouncycastle.bcmath.ec.ECCurve;
import org.bouncycastle.bcmath.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.bcutil.BigIntegers;

/**
 * Basic utility class
 */
class JcaJcePGPUtil
{
    public static SecretKey makeSymmetricKey(
        int             algorithm,
        byte[]          keyBytes)
        throws PGPException
    {
        String    algName = org.bouncycastle.openpgp.PGPUtil.getSymmetricCipherName(algorithm);

        if (algName == null)
        {
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
        throws IOException
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        X9ECParameters x9Params = CustomNamedCurves.getByOID(curveOID);

        if (x9Params == null)
        {
            return ECNamedCurveTable.getByOID(curveOID);
        }

        return x9Params;
    }
}
