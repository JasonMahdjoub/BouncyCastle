package com.distrimind.bouncycastle.crypto.generators;

import com.distrimind.bouncycastle.crypto.CipherKeyGenerator;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.distrimind.bouncycastle.crypto.params.DESParameters;

public class DESKeyGenerator
    extends CipherKeyGenerator
{
    /**
     * initialise the key generator - if strength is set to zero
     * the key generated will be 64 bits in size, otherwise
     * strength can be 64 or 56 bits (if you don't count the parity bits).
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        KeyGenerationParameters param)
    {
        super.init(param);

        if (strength == 0 || strength == (56 / 8))
        {
            strength = DESParameters.DES_KEY_LENGTH;
        }
        else if (strength != DESParameters.DES_KEY_LENGTH)
        {
            throw new IllegalArgumentException("DES key must be "
                    + (DESParameters.DES_KEY_LENGTH * 8)
                    + " bits long.");
        }

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("DESKeyGen", 56, null, CryptoServicePurpose.KEYGEN));
    }

    public byte[] generateKey()
    {
        byte[]  newKey = new byte[DESParameters.DES_KEY_LENGTH];

        do
        {
            random.nextBytes(newKey);

            DESParameters.setOddParity(newKey);
        }
        while (DESParameters.isWeakKey(newKey, 0));

        return newKey;
    }
}
