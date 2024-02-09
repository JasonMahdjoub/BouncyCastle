package com.distrimind.bouncycastle.cms.jcajce;

import java.io.InputStream;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.RecipientOperator;
import com.distrimind.bouncycastle.jcajce.io.CipherInputStream;
import com.distrimind.bouncycastle.operator.InputDecryptor;

public class JceKEKEnvelopedRecipient
    extends JceKEKRecipient
{
    public JceKEKEnvelopedRecipient(SecretKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                return new CipherInputStream(dataOut, dataCipher);
            }
        });
    }
}
