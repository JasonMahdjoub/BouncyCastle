package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

import com.distrimind.bouncycastle.jcajce.spec.AEADParameterSpec;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPUtil;
import com.distrimind.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import com.distrimind.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import com.distrimind.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import com.distrimind.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;

public class JcePBEProtectionRemoverFactory
    implements PBEProtectionRemoverFactory
{
    private final char[] passPhrase;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private PGPDigestCalculatorProvider calculatorProvider;

    private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;

    public JcePBEProtectionRemoverFactory(char[] passPhrase)
    {
        this.passPhrase = passPhrase;
        this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    }

    public JcePBEProtectionRemoverFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
    }

    public JcePBEProtectionRemoverFactory setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBEProtectionRemoverFactory setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(providerName);
        }

        return this;
    }

    public PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException
    {
        if (calculatorProvider == null)
        {
            calculatorProvider = calculatorProviderBuilder.build();
        }

        if (protection.indexOf("ocb") >= 0)
        {
            return new PGPSecretKeyDecryptorWithAAD(passPhrase, calculatorProvider)
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] aad, byte[] keyData,  int keyOff, int keyLen)
                    throws PGPException
                {
                    try
                    {
                        Cipher c;
                        c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/OCB/NoPadding");
                        c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new AEADParameterSpec(iv, 128, aad));
                        return c.doFinal(keyData, keyOff, keyLen);
                    }
                    catch (IllegalBlockSizeException e)
                    {
                        throw new PGPException("illegal block size: " + e.getMessage(), e);
                    }
                    catch (BadPaddingException e)
                    {
                        throw new PGPException("bad padding: " + e.getMessage(), e);
                    }
                    catch (InvalidAlgorithmParameterException e)
                    {
                        throw new PGPException("invalid parameter: " + e.getMessage(), e);
                    }
                    catch (InvalidKeyException e)
                    {
                        throw new PGPException("invalid key: " + e.getMessage(), e);
                    }
                }
            };
        }
        else
        {
            return new PBESecretKeyDecryptor(passPhrase, calculatorProvider)
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                    throws PGPException
                {
                    try
                    {
                        Cipher c;
                        c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/CBC/NoPadding");
                        c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new IvParameterSpec(iv));
                        return c.doFinal(keyData, keyOff, keyLen);
                    }
                    catch (IllegalBlockSizeException e)
                    {
                        throw new PGPException("illegal block size: " + e.getMessage(), e);
                    }
                    catch (BadPaddingException e)
                    {
                        throw new PGPException("bad padding: " + e.getMessage(), e);
                    }
                    catch (InvalidAlgorithmParameterException e)
                    {
                        throw new PGPException("invalid parameter: " + e.getMessage(), e);
                    }
                    catch (InvalidKeyException e)
                    {
                        throw new PGPException("invalid key: " + e.getMessage(), e);
                    }
                }
            };

        }
    }
}
