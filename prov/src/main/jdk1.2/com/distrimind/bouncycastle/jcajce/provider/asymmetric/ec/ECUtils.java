package com.distrimind.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.PrivateKey;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.x9.X962Parameters;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.asn1.x9.X9ECPoint;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;
import com.distrimind.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPoint;

class ECUtils
{
    static AsymmetricKeyParameter generatePrivateKeyParameter(
                PrivateKey key)
        throws InvalidKeyException
    {
        return (key instanceof BCECPrivateKey) ? ((BCECPrivateKey)key).engineGetKeyParameters() : ECUtil.generatePrivateKeyParameter(key);
    }


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
