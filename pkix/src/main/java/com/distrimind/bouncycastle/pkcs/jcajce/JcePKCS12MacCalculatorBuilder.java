package com.distrimind.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.jcajce.PKCS12Key;
import com.distrimind.bouncycastle.jcajce.io.MacOutputStream;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;

public class JcePKCS12MacCalculatorBuilder
    implements PKCS12MacCalculatorBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();
    private ASN1ObjectIdentifier algorithm;

    private SecureRandom random;
    private int saltLength;
    private int iterationCount = 1024;

    public JcePKCS12MacCalculatorBuilder()
    {
        this(OIWObjectIdentifiers.idSHA1);
    }

    public JcePKCS12MacCalculatorBuilder(ASN1ObjectIdentifier hashAlgorithm)
    {
        this.algorithm = hashAlgorithm;
    }

    public JcePKCS12MacCalculatorBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCS12MacCalculatorBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JcePKCS12MacCalculatorBuilder setIterationCount(int iterationCount)
    {
        this.iterationCount = iterationCount;

        return this;
    }

    public AlgorithmIdentifier getDigestAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(algorithm, DERNull.INSTANCE);
    }

    public MacCalculator build(final char[] password)
        throws OperatorCreationException
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        try
        {
            final Mac mac = helper.createMac(algorithm.getId());

            saltLength = mac.getMacLength();
            final byte[] salt = new byte[saltLength];

            random.nextBytes(salt);

            PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);
            final SecretKey key = new PKCS12Key(password);

            mac.init(key, defParams);

            return new MacCalculator()
            {
                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return new AlgorithmIdentifier(algorithm, new PKCS12PBEParams(salt, iterationCount));
                }

                public OutputStream getOutputStream()
                {
                    return new MacOutputStream(mac);
                }

                public byte[] getMac()
                {
                    return mac.doFinal();
                }

                public GenericKey getKey()
                {
                    return new GenericKey(getAlgorithmIdentifier(), key.getEncoded());
                }
            };
        }
        catch (Exception e)
        {
            throw new OperatorCreationException("unable to create MAC calculator: " + e.getMessage(), e);
        }
    }
}
