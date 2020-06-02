package org.bouncycastle.bcjcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcasn1.DERNull;
import org.bouncycastle.bcasn1.x9.X962Parameters;
import org.bouncycastle.bcasn1.x9.X9ECParameters;
import org.bouncycastle.bcasn1.x9.X9ECPoint;
import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;
import org.bouncycastle.bcjcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.bcmath.ec.ECCurve;
import org.bouncycastle.bcmath.ec.ECPoint;

class ECUtils
{
    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPublicKey) ? ((BCECPublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
    }

    static X962Parameters getDomainParametersFromName(ECParameterSpec ecSpec, boolean withCompression)
    {
        X962Parameters params;

        if (ecSpec instanceof ECNamedCurveParameterSpec)
        {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveParameterSpec)ecSpec).getName());

            if (curveOid == null)
            {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveParameterSpec)ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
        }
        else
        {
            ECParameterSpec p = (ECParameterSpec)ecSpec;

            X9ECParameters ecP = new X9ECParameters(
                p.getCurve(), new X9ECPoint(p.getG(), withCompression), p.getN(), p.getH(), p.getSeed());

            params = new X962Parameters(ecP);
        }

        return params;
    }
}
