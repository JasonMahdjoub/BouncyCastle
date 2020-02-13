package org.bouncycastle.bccrypto;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;

public interface KeyParser
{
    AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException;
}
