package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPException;

public interface PBEProtectionRemoverFactory
{
    PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException;
}
