package com.distrimind.bouncycastle.cert.crmf.jcajce;

import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cert.crmf.CRMFException;
import com.distrimind.bouncycastle.jcajce.io.CipherOutputStream;
import com.distrimind.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.distrimind.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.OutputEncryptor;

public class JceCRMFEncryptorBuilder
{
    private ASN1ObjectIdentifier encryptionOID;
    private int                  keySize;

    private CRMFHelper helper = new CRMFHelper(new DefaultJcaJceHelper());
    private SecureRandom random;

    public JceCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, -1);
    }

    public JceCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.keySize = keySize;
    }

    public JceCRMFEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new CRMFHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JceCRMFEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new CRMFHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JceCRMFEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CRMFException
    {
        return new CRMFOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CRMFOutputEncryptor
        implements OutputEncryptor
    {
        private SecretKey encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Cipher cipher;

        CRMFOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CRMFException
        {
            KeyGenerator keyGen = helper.createKeyGenerator(encryptionOID);

            if (random == null)
            {
                random = new SecureRandom();
            }

            if (keySize < 0)
            {
                keyGen.init(random);
            }
            else
            {
                keyGen.init(keySize, random);
            }

            cipher = helper.createCipher(encryptionOID);
            encKey = keyGen.generateKey();
            AlgorithmParameters params = helper.generateParameters(encryptionOID, encKey, random);

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, encKey, params, random);
            }
            catch (InvalidKeyException e)
            {
                throw new CRMFException("unable to initialize cipher: " + e.getMessage(), e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CRMFException("unable to initialize cipher: " + e.getMessage(), e);
            }

            //
            // If params are null we try and second guess on them as some providers don't provide
            // algorithm parameter generation explicity but instead generate them under the hood.
            //
            if (params == null)
            {
                params = cipher.getParameters();
            }

            algorithmIdentifier = helper.getAlgorithmIdentifier(encryptionOID, params);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return new CipherOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new GenericKey(encKey);
        }
    }
}
