package com.distrimind.bouncycastle.operator.jcajce;

import java.io.InputStream;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;
import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.jcajce.io.CipherInputStream;
import com.distrimind.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.JcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.operator.InputDecryptor;
import com.distrimind.bouncycastle.operator.InputDecryptorProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * A generic decryptor provider for IETF style algorithms.
 */
public class JceInputDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JceInputDecryptorProviderBuilder()
    {
    }

    public JceInputDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JceInputDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    /**
     * Build a decryptor provider which will use the passed in bytes for the symmetric key.
     *
     * @param keyBytes bytes representing the key to use.
     * @return an decryptor provider.
     */
    public InputDecryptorProvider build(byte[] keyBytes)
    {
        final byte[] encKeyBytes = Arrays.clone(keyBytes);

        return new InputDecryptorProvider()
        {
            private Cipher cipher;
            private AlgorithmIdentifier encryptionAlg;

            public InputDecryptor get(final AlgorithmIdentifier algorithmIdentifier)
                throws OperatorCreationException
            {
                encryptionAlg = algorithmIdentifier;

                ASN1ObjectIdentifier algorithm = algorithmIdentifier.getAlgorithm();

                try
                {
                    cipher = helper.createCipher(algorithm.getId());
                    SecretKey key = new SecretKeySpec(encKeyBytes, algorithm.getId());
                    
                    ASN1Encodable encParams = algorithmIdentifier.getParameters();

                    if (encParams instanceof ASN1OctetString)
                    {
                        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ASN1OctetString.getInstance(encParams).getOctets()));
                    }
                    else
                    {
                        // TODO: at the moment it's just GOST, but...
                        GOST28147Parameters gParams = GOST28147Parameters.getInstance(encParams);

                        cipher.init(Cipher.DECRYPT_MODE, key, new GOST28147ParameterSpec(gParams.getEncryptionParamSet(), gParams.getIV()));
                    }
                }
                catch (Exception e)
                {
                    throw new OperatorCreationException("unable to create InputDecryptor: " + e.getMessage(), e);
                }

                return new InputDecryptor()
                {
                    public AlgorithmIdentifier getAlgorithmIdentifier()
                    {
                        return encryptionAlg;
                    }

                    public InputStream getInputStream(InputStream input)
                    {
                        return new CipherInputStream(input, cipher);
                    }
                };
            }
        };
    }
}
