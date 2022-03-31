package com.distrimind.bouncycastle.crypto;

import java.io.IOException;
import java.io.InputStream;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
