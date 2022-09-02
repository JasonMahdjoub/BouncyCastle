package com.distrimind.bouncycastle.its.bc;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.nist.NISTNamedCurves;
import com.distrimind.bouncycastle.asn1.sec.SECObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import com.distrimind.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ECNamedDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.its.ITSPublicEncryptionKey;
import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.BasePublicEncryptionKey;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.EccCurvePoint;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.EccP384CurvePoint;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes.SymmAlgorithm;

public class BcITSPublicEncryptionKey
    extends ITSPublicEncryptionKey
{
    public BcITSPublicEncryptionKey(PublicEncryptionKey encryptionKey)
    {
        super(encryptionKey);
    }

    static PublicEncryptionKey fromKeyParameters(ECPublicKeyParameters pubKey)
    {
        ASN1ObjectIdentifier curveID = ((ECNamedDomainParameters)pubKey.getParameters()).getName();
        ECPoint q = pubKey.getQ();

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesNistP256)
                    .setValue(EccP256CurvePoint
                        .uncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()))
                    .createBasePublicEncryptionKey());
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new PublicEncryptionKey(
                SymmAlgorithm.aes128Ccm,
                new BasePublicEncryptionKey.Builder()
                    .setChoice(BasePublicEncryptionKey.eciesBrainpoolP256r1)
                    .setValue(EccP256CurvePoint
                        .uncompressedP256(
                            q.getAffineXCoord().toBigInteger(),
                            q.getAffineYCoord().toBigInteger()))
                    .createBasePublicEncryptionKey());
        }
        else
        {
            throw new IllegalArgumentException("unknown curve in public encryption key");
        }
    }

    public BcITSPublicEncryptionKey(AsymmetricKeyParameter encryptionKey)
    {
        super(fromKeyParameters((ECPublicKeyParameters)encryptionKey));
    }

    public AsymmetricKeyParameter getKey()
    {
        X9ECParameters params;

        BasePublicEncryptionKey baseKey = encryptionKey.getPublicKey();
        ASN1ObjectIdentifier curveID;

        switch (baseKey.getChoice())
        {
        case BasePublicEncryptionKey.eciesNistP256:
            curveID = SECObjectIdentifiers.secp256r1;
            params = NISTNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
            break;
        case BasePublicEncryptionKey.eciesBrainpoolP256r1:
            curveID = TeleTrusTObjectIdentifiers.brainpoolP256r1;
            params = TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1);
            break;
        default:
            throw new IllegalStateException("unknown key type");
        }
        ECCurve curve = params.getCurve();

        ASN1Encodable pviCurvePoint = encryptionKey.getPublicKey().getBasePublicEncryptionKey();
        final EccCurvePoint itsPoint;
        if (pviCurvePoint instanceof EccCurvePoint)
        {
            itsPoint = (EccCurvePoint)baseKey.getBasePublicEncryptionKey();
        }
        else
        {
            throw new IllegalStateException("extension to public verification key not supported");
        }

        byte[] key;

        if (itsPoint instanceof EccP256CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else if (itsPoint instanceof EccP384CurvePoint)
        {
            key = itsPoint.getEncodedPoint();
        }
        else
        {
            throw new IllegalStateException("unknown key type");
        }

        ECPoint point = curve.decodePoint(key).normalize();
        return new ECPublicKeyParameters(point,
            new ECNamedDomainParameters(curveID, params));
    }
}
