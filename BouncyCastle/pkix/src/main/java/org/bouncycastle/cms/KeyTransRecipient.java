package org.bouncycastle.cms;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;

public interface KeyTransRecipient
    extends Recipient
{
    RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        throws CMSException;
}
