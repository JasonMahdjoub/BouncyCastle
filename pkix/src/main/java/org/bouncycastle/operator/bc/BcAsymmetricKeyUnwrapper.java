package org.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;

public abstract class BcAsymmetricKeyUnwrapper
    extends AsymmetricKeyUnwrapper
{
    private AsymmetricKeyParameter privateKey;

    public BcAsymmetricKeyUnwrapper(AlgorithmIdentifier encAlgId, AsymmetricKeyParameter privateKey)
    {
        super(encAlgId);

        this.privateKey = privateKey;
    }

    public GenericKey generateUnwrappedKey(AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedKey)
        throws OperatorException
    {
        AsymmetricBlockCipher keyCipher = createAsymmetricUnwrapper(this.getAlgorithmIdentifier().getAlgorithm());

        keyCipher.init(false, privateKey);
        try
        {
            byte[] key = keyCipher.processBlock(encryptedKey, 0, encryptedKey.length);

            if (encryptedKeyAlgorithm.getAlgorithm().equals(PKCSObjectIdentifiers.des_EDE3_CBC))
            {
                return new GenericKey(encryptedKeyAlgorithm, key);
            }
            else
            {
                return new GenericKey(encryptedKeyAlgorithm, key);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new OperatorException("unable to recover secret key: " + e.getMessage(), e);
        }
    }

    protected abstract AsymmetricBlockCipher createAsymmetricUnwrapper(ASN1ObjectIdentifier algorithm);
}
