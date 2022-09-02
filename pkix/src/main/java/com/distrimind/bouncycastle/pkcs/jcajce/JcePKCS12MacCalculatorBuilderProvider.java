package com.distrimind.bouncycastle.pkcs.jcajce;

import java.io.OutputStream;
import java.security.Provider;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.DERNull;
import com.distrimind.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import com.distrimind.bouncycastle.pkcs.PKCS12MacCalculatorBuilderProvider;
import com.distrimind.bouncycastle.jcajce.PKCS12Key;
import com.distrimind.bouncycastle.jcajce.io.MacOutputStream;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;

public class JcePKCS12MacCalculatorBuilderProvider
    implements PKCS12MacCalculatorBuilderProvider
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePKCS12MacCalculatorBuilderProvider()
    {
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePKCS12MacCalculatorBuilderProvider setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PKCS12MacCalculatorBuilder get(final AlgorithmIdentifier algorithmIdentifier)
    {
        return new PKCS12MacCalculatorBuilder()
        {
            public MacCalculator build(final char[] password)
                throws OperatorCreationException
            {
                final PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

                try
                {
                    final ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                    final Mac mac = helper.createMac(algorithm.getId());

                    PBEParameterSpec defParams = new PBEParameterSpec(pbeParams.getIV(), pbeParams.getIterations().intValue());

                    final SecretKey key = new PKCS12Key(password);

                    mac.init(key, defParams);

                    return new MacCalculator()
                    {
                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return new AlgorithmIdentifier(algorithm, pbeParams);
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

            public AlgorithmIdentifier getDigestAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
            }
        };
    }
}
