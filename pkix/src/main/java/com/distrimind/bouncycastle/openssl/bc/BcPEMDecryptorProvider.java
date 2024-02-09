package com.distrimind.bouncycastle.openssl.bc;

import com.distrimind.bouncycastle.openssl.PEMDecryptor;
import com.distrimind.bouncycastle.openssl.PEMDecryptorProvider;
import com.distrimind.bouncycastle.openssl.PEMException;
import com.distrimind.bouncycastle.openssl.PasswordException;

public class BcPEMDecryptorProvider
    implements PEMDecryptorProvider
{
    private final char[] password;

    public BcPEMDecryptorProvider(char[] password)
    {
        this.password = password;
    }

    public PEMDecryptor get(final String dekAlgName)
    {
        return new PEMDecryptor()
        {
            public byte[] decrypt(byte[] keyBytes, byte[] iv)
                throws PEMException
            {
                if (password == null)
                {
                    throw new PasswordException("Password is null, but a password is required");
                }

                return PEMUtilities.crypt(false, keyBytes, password, dekAlgName, iv);
            }
        };
    }
}
