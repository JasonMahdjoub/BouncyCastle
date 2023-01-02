package com.distrimind.bouncycastle.cms.bc;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.operator.AsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.operator.OperatorException;
import com.distrimind.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;
import com.distrimind.bouncycastle.cms.CMSException;
import com.distrimind.bouncycastle.cms.KeyTransRecipient;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public abstract class BcKeyTransRecipient
    implements KeyTransRecipient
{
    private AsymmetricKeyParameter recipientKey;

    public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);

        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
