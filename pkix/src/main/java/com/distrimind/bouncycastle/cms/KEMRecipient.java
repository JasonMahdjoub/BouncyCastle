package com.distrimind.bouncycastle.cms;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KEMRecipient
    extends Recipient
{
    RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        throws CMSException;
}
