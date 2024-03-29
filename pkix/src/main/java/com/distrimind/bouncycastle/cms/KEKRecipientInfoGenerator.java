package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.ASN1OctetString;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.OperatorException;
import com.distrimind.bouncycastle.operator.SymmetricKeyWrapper;
import com.distrimind.bouncycastle.asn1.cms.KEKIdentifier;
import com.distrimind.bouncycastle.asn1.cms.KEKRecipientInfo;
import com.distrimind.bouncycastle.asn1.cms.RecipientInfo;

public abstract class KEKRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private final KEKIdentifier kekIdentifier;

    protected final SymmetricKeyWrapper wrapper;

    protected KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SymmetricKeyWrapper wrapper)
    {
        this.kekIdentifier = kekIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException
    {
        try
        {
            ASN1OctetString encryptedKey = new DEROctetString(wrapper.generateWrappedKey(contentEncryptionKey));

            return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, wrapper.getAlgorithmIdentifier(), encryptedKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }
    }
}