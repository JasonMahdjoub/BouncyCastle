package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.operator.AsymmetricKeyWrapper;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.OperatorException;
import com.distrimind.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import com.distrimind.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import com.distrimind.bouncycastle.asn1.cms.RecipientIdentifier;
import com.distrimind.bouncycastle.asn1.cms.RecipientInfo;

public abstract class KeyTransRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    protected final AsymmetricKeyWrapper wrapper;

    private IssuerAndSerialNumber issuerAndSerial;
    private byte[] subjectKeyIdentifier;

    protected KeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, AsymmetricKeyWrapper wrapper)
    {
        this.issuerAndSerial = issuerAndSerial;
        this.wrapper = wrapper;
    }

    protected KeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AsymmetricKeyWrapper wrapper)
    {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        byte[] encryptedKeyBytes;
        try
        {
            encryptedKeyBytes = wrapper.generateWrappedKey(contentEncryptionKey);
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }

        RecipientIdentifier recipId;
        if (issuerAndSerial != null)
        {
            recipId = new RecipientIdentifier(issuerAndSerial);
        }
        else
        {
            recipId = new RecipientIdentifier(new DEROctetString(subjectKeyIdentifier));
        }

        return new RecipientInfo(new KeyTransRecipientInfo(recipId, wrapper.getAlgorithmIdentifier(),
            new DEROctetString(encryptedKeyBytes)));
    }
}