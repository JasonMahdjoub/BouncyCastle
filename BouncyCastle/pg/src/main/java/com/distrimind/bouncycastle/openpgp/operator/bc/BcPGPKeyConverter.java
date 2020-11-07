package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.asn1.x9.X9ECParameters;
import com.distrimind.bouncycastle.bcpg.BCPGKey;
import com.distrimind.bouncycastle.bcpg.DSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.DSASecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.ECDHPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.ECPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.ECSecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.EdDSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.EdSecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.HashAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.bcpg.RSAPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.RSASecretBCPGKey;
import com.distrimind.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.DSAParameters;
import com.distrimind.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.DSAPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECNamedDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ElGamalParameters;
import com.distrimind.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.RSAKeyParameters;
import com.distrimind.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.X25519PublicKeyParameters;
import com.distrimind.bouncycastle.crypto.util.PrivateKeyFactory;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.openpgp.PGPAlgorithmParameters;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPKdfParameters;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.BigIntegers;

public class BcPGPKeyConverter
{
    // We default to these as they are specified as mandatory in RFC 6631.
    private static final PGPKdfParameters DEFAULT_KDF_PARAMETERS = new PGPKdfParameters(HashAlgorithmTags.SHA256,
        SymmetricKeyAlgorithmTags.AES_128);

    public PGPPrivateKey getPGPPrivateKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        BCPGKey privPk = getPrivateBCPGKey(pubKey, privKey);

        return new PGPPrivateKey(pubKey.getKeyID(), pubKey.getPublicKeyPacket(), privPk);
    }

    /**
     * Create a PGPPublicKey from the passed in JCA one.
     * <p>
     * Note: the time passed in affects the value of the key's keyID, so you probably only want
     * to do this once for a JCA key, or make sure you keep track of the time you used.
     * </p>
     * @param algorithm asymmetric algorithm type representing the public key.
     * @param pubKey    actual public key to associate.
     * @param time      date of creation.
     * @throws PGPException on key creation problem.
     */
    public PGPPublicKey getPGPPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, AsymmetricKeyParameter pubKey, Date time)
        throws PGPException
    {
        BCPGKey bcpgKey = getPublicBCPGKey(algorithm, algorithmParameters, pubKey, time);

        return new PGPPublicKey(new PublicKeyPacket(algorithm, time, bcpgKey), new BcKeyFingerprintCalculator());
    }

    public AsymmetricKeyParameter getPrivateKey(PGPPrivateKey privKey)
        throws PGPException
    {
        PublicKeyPacket pubPk = privKey.getPublicKeyPacket();
        BCPGKey privPk = privKey.getPrivateKeyDataPacket();

        try
        {
            switch (pubPk.getAlgorithm())
            {
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicBCPGKey dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
                DSASecretBCPGKey dsaPriv = (DSASecretBCPGKey)privPk;
                return new DSAPrivateKeyParameters(dsaPriv.getX(),
                    new DSAParameters(dsaPub.getP(), dsaPub.getQ(), dsaPub.getG()));
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhPub = (ECDHPublicBCPGKey)pubPk.getKey();
                ECSecretBCPGKey ecdhK = (ECSecretBCPGKey)privPk;

                if (CryptlibObjectIdentifiers.curvey25519.equals(ecdhPub.getCurveOID()))
                {
                    // 'reverse' because the native format for X25519 private keys is little-endian
                    return implGetPrivateKeyPKCS8(new PrivateKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        new DEROctetString(Arrays.reverse(BigIntegers.asUnsignedByteArray(ecdhK.getX())))));
                }
                else
                {
                    return implGetPrivateKeyEC(ecdhPub, ecdhK);
                }
            }

            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPrivateKeyEC((ECDSAPublicBCPGKey)pubPk.getKey(), (ECSecretBCPGKey)privPk);

            case PublicKeyAlgorithmTags.EDDSA:
            {
                EdSecretBCPGKey eddsaK = (EdSecretBCPGKey)privPk;

                return implGetPrivateKeyPKCS8(new PrivateKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    new DEROctetString(BigIntegers.asUnsignedByteArray(eddsaK.getX()))));
            }

            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            {
                ElGamalPublicBCPGKey elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
                ElGamalSecretBCPGKey elPriv = (ElGamalSecretBCPGKey)privPk;
                return new ElGamalPrivateKeyParameters(elPriv.getX(), new ElGamalParameters(elPub.getP(), elPub.getG()));
            }

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
                RSASecretBCPGKey rsaPriv = (RSASecretBCPGKey)privPk;
                return new RSAPrivateCrtKeyParameters(rsaPriv.getModulus(), rsaPub.getPublicExponent(),
                    rsaPriv.getPrivateExponent(), rsaPriv.getPrimeP(), rsaPriv.getPrimeQ(), rsaPriv.getPrimeExponentP(),
                    rsaPriv.getPrimeExponentQ(), rsaPriv.getCrtCoefficient());
            }

            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
    }

    public AsymmetricKeyParameter getPublicKey(PGPPublicKey publicKey)
        throws PGPException
    {
        PublicKeyPacket publicPk = publicKey.getPublicKeyPacket();

        try
        {
            switch (publicPk.getAlgorithm())
            {
            case PublicKeyAlgorithmTags.DSA:
            {
                DSAPublicBCPGKey dsaK = (DSAPublicBCPGKey)publicPk.getKey();
                return new DSAPublicKeyParameters(dsaK.getY(), new DSAParameters(dsaK.getP(), dsaK.getQ(), dsaK.getG()));
            }

            case PublicKeyAlgorithmTags.ECDH:
            {
                ECDHPublicBCPGKey ecdhK = (ECDHPublicBCPGKey)publicPk.getKey();

                if (ecdhK.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    byte[] pEnc = BigIntegers.asUnsignedByteArray(ecdhK.getEncodedPoint());

                    // skip the 0x40 header byte.
                    if (pEnc.length < 1 || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    return implGetPublicKeyX509(new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519),
                        Arrays.copyOfRange(pEnc, 1, pEnc.length)));
                }
                else
                {
                    return implGetPublicKeyEC(ecdhK);
                }
            }

            case PublicKeyAlgorithmTags.ECDSA:
                return implGetPublicKeyEC((ECDSAPublicBCPGKey)publicPk.getKey());

            case PublicKeyAlgorithmTags.EDDSA:
            {
                EdDSAPublicBCPGKey eddsaK = (EdDSAPublicBCPGKey)publicPk.getKey();

                byte[] pEnc = BigIntegers.asUnsignedByteArray(eddsaK.getEncodedPoint());

                // skip the 0x40 header byte.
                if (pEnc.length < 1 || 0x40 != pEnc[0])
                {
                    throw new IllegalArgumentException("Invalid Ed25519 public key");
                }

                return implGetPublicKeyX509(new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                    Arrays.copyOfRange(pEnc, 1, pEnc.length)));
            }

            case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
            case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey elK = (ElGamalPublicBCPGKey)publicPk.getKey();
                return new ElGamalPublicKeyParameters(elK.getY(), new ElGamalParameters(elK.getP(), elK.getG()));

            case PublicKeyAlgorithmTags.RSA_ENCRYPT:
            case PublicKeyAlgorithmTags.RSA_GENERAL:
            case PublicKeyAlgorithmTags.RSA_SIGN:
            {
                RSAPublicBCPGKey rsaK = (RSAPublicBCPGKey)publicPk.getKey();
                return new RSAKeyParameters(false, rsaK.getModulus(), rsaK.getPublicExponent());
            }

            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("exception constructing public key", e);
        }
    }

    private BCPGKey getPrivateBCPGKey(PGPPublicKey pubKey, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        switch (pubKey.getAlgorithm())
        {
        case PublicKeyAlgorithmTags.DSA:
        {
            DSAPrivateKeyParameters dsK = (DSAPrivateKeyParameters)privKey;
            return new DSASecretBCPGKey(dsK.getX());
        }

        case PublicKeyAlgorithmTags.ECDH:
        {
            if (privKey instanceof ECPrivateKeyParameters)
            {
                ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
                return new ECSecretBCPGKey(ecK.getD());
            }
            else
            {
                // 'reverse' because the native format for X25519 private keys is little-endian
                X25519PrivateKeyParameters xK = (X25519PrivateKeyParameters)privKey;
                return new ECSecretBCPGKey(new BigInteger(1, Arrays.reverse(xK.getEncoded())));
            }
        }

        case PublicKeyAlgorithmTags.ECDSA:
        {
            ECPrivateKeyParameters ecK = (ECPrivateKeyParameters)privKey;
            return new ECSecretBCPGKey(ecK.getD());
        }

        case PublicKeyAlgorithmTags.EDDSA:
        {
            Ed25519PrivateKeyParameters edK = (Ed25519PrivateKeyParameters)privKey;
            return new EdSecretBCPGKey(new BigInteger(1, edK.getEncoded()));
        }

        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
        {
            ElGamalPrivateKeyParameters esK = (ElGamalPrivateKeyParameters)privKey;
            return new ElGamalSecretBCPGKey(esK.getX());
        }

        case PublicKeyAlgorithmTags.RSA_ENCRYPT:
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
        {
            RSAPrivateCrtKeyParameters rsK = (RSAPrivateCrtKeyParameters)privKey;
            return new RSASecretBCPGKey(rsK.getExponent(), rsK.getP(), rsK.getQ());
        }

        default:
            throw new PGPException("unknown key class");
        }
    }

    private BCPGKey getPublicBCPGKey(int algorithm, PGPAlgorithmParameters algorithmParameters,
        AsymmetricKeyParameter pubKey, Date time) throws PGPException
    {
        if (pubKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters rK = (RSAKeyParameters)pubKey;
            return new RSAPublicBCPGKey(rK.getModulus(), rK.getExponent());
        }
        else if (pubKey instanceof DSAPublicKeyParameters)
        {
            DSAPublicKeyParameters dK = (DSAPublicKeyParameters)pubKey;
            DSAParameters dP = dK.getParameters();
            return new DSAPublicBCPGKey(dP.getP(), dP.getQ(), dP.getG(), dK.getY());
        }
        else if (pubKey instanceof ElGamalPublicKeyParameters)
        {
            ElGamalPublicKeyParameters eK = (ElGamalPublicKeyParameters)pubKey;
            ElGamalParameters eS = eK.getParameters();
            return new ElGamalPublicBCPGKey(eS.getP(), eS.getG(), eK.getY());
        }
        else if (pubKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters ecK = (ECPublicKeyParameters)pubKey;

            // TODO Should we have a way to recognize named curves when the name is missing?
            ECNamedDomainParameters parameters = (ECNamedDomainParameters)ecK.getParameters();

            if (algorithm == PGPPublicKey.ECDH)
            {
                PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

                return new ECDHPublicBCPGKey(parameters.getName(), ecK.getQ(), kdfParams.getHashAlgorithm(),
                    kdfParams.getSymmetricWrapAlgorithm());
            }
            else if (algorithm == PGPPublicKey.ECDSA)
            {
                return new ECDSAPublicBCPGKey(parameters.getName(), ecK.getQ());
            }
            else
            {
                throw new PGPException("unknown EC algorithm");
            }
        }
        else if (pubKey instanceof Ed25519PublicKeyParameters)
        {
            byte[] pointEnc = new byte[1 + Ed25519PublicKeyParameters.KEY_SIZE];
            pointEnc[0] = 0x40;
            ((Ed25519PublicKeyParameters)pubKey).encode(pointEnc, 1);
            return new EdDSAPublicBCPGKey(GNUObjectIdentifiers.Ed25519, new BigInteger(1, pointEnc));
        }
        else if (pubKey instanceof X25519PublicKeyParameters)
        {
            byte[] pointEnc = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
            pointEnc[0] = 0x40;
            ((X25519PublicKeyParameters)pubKey).encode(pointEnc, 1);

            PGPKdfParameters kdfParams = implGetKdfParameters(algorithmParameters);

            return new ECDHPublicBCPGKey(CryptlibObjectIdentifiers.curvey25519, new BigInteger(1, pointEnc),
                kdfParams.getHashAlgorithm(), kdfParams.getSymmetricWrapAlgorithm());
        }
        else
        {
            throw new PGPException("unknown key class");
        }
    }

    private PGPKdfParameters implGetKdfParameters(PGPAlgorithmParameters algorithmParameters)
    {
        return null == algorithmParameters ? DEFAULT_KDF_PARAMETERS : (PGPKdfParameters)algorithmParameters;
    }

    private ECNamedDomainParameters implGetParametersEC(ECPublicBCPGKey ecPub)
    {
        ASN1ObjectIdentifier curveOID = ecPub.getCurveOID();
        X9ECParameters x9 = BcUtil.getX9Parameters(curveOID);
        return new ECNamedDomainParameters(curveOID, x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
    }

    private AsymmetricKeyParameter implGetPrivateKeyEC(ECPublicBCPGKey ecPub, ECSecretBCPGKey ecPriv)
        throws IOException, PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        return new ECPrivateKeyParameters(ecPriv.getX(), parameters);
    }

    private AsymmetricKeyParameter implGetPrivateKeyPKCS8(PrivateKeyInfo privateKeyInfo) throws IOException
    {
        return PrivateKeyFactory.createKey(privateKeyInfo);
    }

    private AsymmetricKeyParameter implGetPublicKeyEC(ECPublicBCPGKey ecPub) throws IOException, PGPException
    {
        ECNamedDomainParameters parameters = implGetParametersEC(ecPub);
        ECPoint pubPoint = BcUtil.decodePoint(ecPub.getEncodedPoint(), parameters.getCurve());
        return new ECPublicKeyParameters(pubPoint, parameters);
    }

    private AsymmetricKeyParameter implGetPublicKeyX509(SubjectPublicKeyInfo subjectPublicKeyInfo) throws IOException
    {
        return PublicKeyFactory.createKey(subjectPublicKeyInfo);
    }
}
