package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.modes.AEADBlockCipher;
import com.distrimind.bouncycastle.crypto.params.AEADParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;

final class BcTlsAEADCipherImpl
    implements TlsAEADCipherImpl
{
    private final boolean isEncrypting;
    private final AEADBlockCipher cipher;

    private KeyParameter key;

    BcTlsAEADCipherImpl(AEADBlockCipher cipher, boolean isEncrypting)
    {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void init(byte[] nonce, int macSize, byte[] additionalData)
    {
        cipher.init(isEncrypting, new AEADParameters(key, macSize * 8, nonce, additionalData));
    }

    public int getOutputSize(int inputLength)
    {
        return cipher.getOutputSize(inputLength);
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] extraInput, byte[] output,
        int outputOffset) throws IOException
    {
        int len = cipher.processBytes(input, inputOffset, inputLength, output, outputOffset);
    
        int extraInputLength = extraInput.length;
        if (extraInputLength > 0)
        {
            if (!isEncrypting)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
    
            len += cipher.processBytes(extraInput, 0, extraInputLength, output, outputOffset + len);
        }
    
        try
        {
            len += cipher.doFinal(output, outputOffset + len);
        }
        catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
        }

        return len;
    }
}