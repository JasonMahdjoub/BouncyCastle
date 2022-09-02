package com.distrimind.bouncycastle.openssl;

import com.distrimind.bouncycastle.operator.OperatorCreationException;

public interface PEMDecryptorProvider
{
    PEMDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}
