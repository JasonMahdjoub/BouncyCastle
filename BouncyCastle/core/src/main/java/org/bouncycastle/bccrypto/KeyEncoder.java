package org.bouncycastle.bccrypto;

import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}
