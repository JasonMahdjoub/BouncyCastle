package com.distrimind.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.security.Key;

import javax.crypto.Mac;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.RecipientOperator;
import com.distrimind.bouncycastle.jcajce.io.MacOutputStream;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.operator.jcajce.JceGenericKey;

public class JcePasswordAuthenticatedRecipient
    extends JcePasswordRecipient
{
    public JcePasswordAuthenticatedRecipient(char[] password)
    {
        super(password);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentMacAlgorithm, byte[] derivedKey, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, derivedKey, encryptedContentEncryptionKey);

        final Mac dataMac = helper.createContentMac(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new MacCalculator()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentMacAlgorithm;
            }

            public GenericKey getKey()
            {
                return new JceGenericKey(contentMacAlgorithm, secretKey);
            }

            public OutputStream getOutputStream()
            {
                return new MacOutputStream(dataMac);
            }

            public byte[] getMac()
            {
                return dataMac.doFinal();
            }
        });
    }
}
