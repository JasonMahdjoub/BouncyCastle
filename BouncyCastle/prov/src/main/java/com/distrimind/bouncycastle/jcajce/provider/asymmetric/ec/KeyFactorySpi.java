package com.distrimind.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import com.distrimind.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import com.distrimind.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import com.distrimind.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.distrimind.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import com.distrimind.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.jce.spec.ECParameterSpec;
import com.distrimind.bouncycastle.jce.spec.ECPrivateKeySpec;
import com.distrimind.bouncycastle.jce.spec.ECPublicKeySpec;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    String algorithm;
    ProviderConfiguration configuration;

    KeyFactorySpi(
        String algorithm,
        ProviderConfiguration configuration)
    {
        this.algorithm = algorithm;
        this.configuration = configuration;
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        if (key instanceof ECPublicKey)
        {
            return new BCECPublicKey((ECPublicKey)key, configuration);
        }
        else if (key instanceof ECPrivateKey)
        {
            return new BCECPrivateKey((ECPrivateKey)key, configuration);
        }

        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(java.security.spec.ECPublicKeySpec.class) && key instanceof ECPublicKey)
        {
            ECPublicKey k = (ECPublicKey)key;
            if (k.getParams() != null)
            {
                return new java.security.spec.ECPublicKeySpec(k.getW(), k.getParams());
            }
            else
            {
                ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

                return new java.security.spec.ECPublicKeySpec(k.getW(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
            }
        }
        else if (spec.isAssignableFrom(java.security.spec.ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
        {
            ECPrivateKey k = (ECPrivateKey)key;

            if (k.getParams() != null)
            {
                return new java.security.spec.ECPrivateKeySpec(k.getS(), k.getParams());
            }
            else
            {
                ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

                return new java.security.spec.ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
            }
        }
        else if (spec.isAssignableFrom(com.distrimind.bouncycastle.jce.spec.ECPublicKeySpec.class) && key instanceof ECPublicKey)
        {
            ECPublicKey k = (ECPublicKey)key;
            if (k.getParams() != null)
            {
                return new com.distrimind.bouncycastle.jce.spec.ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW()), EC5Util.convertSpec(k.getParams()));
            }
            else
            {
                ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

                return new com.distrimind.bouncycastle.jce.spec.ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW()), implicitSpec);
            }
        }
        else if (spec.isAssignableFrom(com.distrimind.bouncycastle.jce.spec.ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
        {
            ECPrivateKey k = (ECPrivateKey)key;

            if (k.getParams() != null)
            {
                return new com.distrimind.bouncycastle.jce.spec.ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(k.getParams()));
            }
            else
            {
                ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

                return new com.distrimind.bouncycastle.jce.spec.ECPrivateKeySpec(k.getS(), implicitSpec);
            }
        }
        else if (spec.isAssignableFrom(OpenSSHPublicKeySpec.class) && key instanceof ECPublicKey)
        {
            if (key instanceof BCECPublicKey)
            {
                BCECPublicKey bcPk = (BCECPublicKey)key;
                ECParameterSpec sc = bcPk.getParameters();
                try
                {
                    return new OpenSSHPublicKeySpec(
                        OpenSSHPublicKeyUtil.encodePublicKey(
                            new ECPublicKeyParameters(bcPk.getQ(), new ECDomainParameters(sc.getCurve(), sc.getG(), sc.getN(), sc.getH(), sc.getSeed()))));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("unable to produce encoding: " + e.getMessage());
                }
            }
            else
            {
                throw new IllegalArgumentException("invalid key type: " + key.getClass().getName());
            }
        }
        else if (spec.isAssignableFrom(OpenSSHPrivateKeySpec.class) && key instanceof ECPrivateKey)
        {
            if (key instanceof BCECPrivateKey)
            {
                try
                {
                    return new OpenSSHPrivateKeySpec(PrivateKeyInfo.getInstance(key.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("cannot encoded key: " + e.getMessage());
                }
            }
            else
            {
                throw new IllegalArgumentException("invalid key type: " + key.getClass().getName());
            }

        }
        else if (spec.isAssignableFrom(com.distrimind.bouncycastle.jce.spec.OpenSSHPublicKeySpec.class) && key instanceof ECPublicKey)
        {
            if (key instanceof BCECPublicKey)
            {
                BCECPublicKey bcPk = (BCECPublicKey)key;
                ECParameterSpec sc = bcPk.getParameters();
                try
                {
                    return new com.distrimind.bouncycastle.jce.spec.OpenSSHPublicKeySpec(
                        OpenSSHPublicKeyUtil.encodePublicKey(
                            new ECPublicKeyParameters(bcPk.getQ(), new ECDomainParameters(sc.getCurve(), sc.getG(), sc.getN(), sc.getH(), sc.getSeed()))));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("unable to produce encoding: " + e.getMessage());
                }
            }
            else
            {
                throw new IllegalArgumentException("invalid key type: " + key.getClass().getName());
            }
        }
        else if (spec.isAssignableFrom(com.distrimind.bouncycastle.jce.spec.OpenSSHPrivateKeySpec.class) && key instanceof ECPrivateKey)
        {
            if (key instanceof BCECPrivateKey)
            {
                try
                {
                    return new com.distrimind.bouncycastle.jce.spec.OpenSSHPrivateKeySpec(PrivateKeyInfo.getInstance(key.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("cannot encoded key: " + e.getMessage());
                }
            }
            else
            {
                throw new IllegalArgumentException("invalid key type: " + key.getClass().getName());
            }
        }

        return super.engineGetKeySpec(key, spec);
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof ECPrivateKeySpec)
        {
            return new BCECPrivateKey(algorithm, (ECPrivateKeySpec)keySpec, configuration);
        }
        else if (keySpec instanceof java.security.spec.ECPrivateKeySpec)
        {
            return new BCECPrivateKey(algorithm, (java.security.spec.ECPrivateKeySpec)keySpec, configuration);
        }
        else if (keySpec instanceof OpenSSHPrivateKeySpec)
        {
            com.distrimind.bouncycastle.asn1.sec.ECPrivateKey ecKey = com.distrimind.bouncycastle.asn1.sec.ECPrivateKey.getInstance(((OpenSSHPrivateKeySpec)keySpec).getEncoded());

            try
            {
                return new BCECPrivateKey(algorithm, new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecKey.getParameters()), ecKey), configuration);
            }
            catch (IOException e)
            {
                throw new InvalidKeySpecException("bad encoding: " + e.getMessage());
            }
        }

        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        try
        {
            if (keySpec instanceof ECPublicKeySpec)
            {
                return new BCECPublicKey(algorithm, (ECPublicKeySpec)keySpec, configuration);
            }
            else if (keySpec instanceof java.security.spec.ECPublicKeySpec)
            {
                return new BCECPublicKey(algorithm, (java.security.spec.ECPublicKeySpec)keySpec, configuration);
            }
            else if (keySpec instanceof OpenSSHPublicKeySpec)
            {
                CipherParameters params = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
                if (params instanceof ECPublicKeyParameters)
                {
                    ECDomainParameters parameters = ((ECPublicKeyParameters)params).getParameters();
                    return engineGeneratePublic(
                        new ECPublicKeySpec(((ECPublicKeyParameters)params).getQ(),
                            new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH(), parameters.getSeed())
                        ));
                }
                else
                {
                    throw new IllegalArgumentException("openssh key is not ec public key");
                }
            }
        }
        catch (Exception e)
        {
            throw new InvalidKeySpecException("invalid KeySpec: " + e.getMessage(), e);
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            return new BCECPrivateKey(algorithm, keyInfo, configuration);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            return new BCECPublicKey(algorithm, keyInfo, configuration);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public static class EC
        extends KeyFactorySpi
    {
        public EC()
        {
            super("EC", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECDSA
        extends KeyFactorySpi
    {
        public ECDSA()
        {
            super("ECDSA", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECGOST3410
        extends KeyFactorySpi
    {
        public ECGOST3410()
        {
            super("ECGOST3410", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECGOST3410_2012
        extends KeyFactorySpi
    {
        public ECGOST3410_2012()
        {
            super("ECGOST3410-2012", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECDH
        extends KeyFactorySpi
    {
        public ECDH()
        {
            super("ECDH", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECDHC
        extends KeyFactorySpi
    {
        public ECDHC()
        {
            super("ECDHC", BouncyCastleProvider.CONFIGURATION);
        }
    }

    public static class ECMQV
        extends KeyFactorySpi
    {
        public ECMQV()
        {
            super("ECMQV", BouncyCastleProvider.CONFIGURATION);
        }
    }
}