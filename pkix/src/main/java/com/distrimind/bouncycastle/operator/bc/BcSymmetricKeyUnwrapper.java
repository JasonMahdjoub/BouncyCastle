package com.distrimind.bouncycastle.operator.bc;

import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.operator.GenericKey;
import com.distrimind.bouncycastle.operator.OperatorException;
import com.distrimind.bouncycastle.operator.SymmetricKeyUnwrapper;

public class BcSymmetricKeyUnwrapper
    extends SymmetricKeyUnwrapper
{
    private SecureRandom random;
    private Wrapper wrapper;
    private KeyParameter wrappingKey;

    public BcSymmetricKeyUnwrapper(AlgorithmIdentifier wrappingAlgorithm, Wrapper wrapper, KeyParameter wrappingKey)
    {
        super(wrappingAlgorithm);

        this.wrapper = wrapper;
        this.wrappingKey = wrappingKey;
    }

    public BcSymmetricKeyUnwrapper setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        wrapper.init(false, wrappingKey);

        try
        {
            return new GenericKey(encryptedKeyAlgorithm, wrapper.unwrap(encryptedKey, 0, encryptedKey.length));
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to unwrap key: " + e.getMessage(), e);
        }
    }
}
