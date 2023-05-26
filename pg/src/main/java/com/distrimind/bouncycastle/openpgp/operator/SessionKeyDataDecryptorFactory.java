package com.distrimind.bouncycastle.openpgp.operator;

import com.distrimind.bouncycastle.openpgp.PGPSessionKey;

public interface SessionKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    PGPSessionKey getSessionKey();
}
