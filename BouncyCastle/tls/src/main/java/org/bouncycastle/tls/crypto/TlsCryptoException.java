package com.distrimind.bouncycastle.tls.crypto;

import com.distrimind.bouncycastle.tls.TlsException;

/**
 * Basic exception class for crypto services to pass back a cause.
 */
public class TlsCryptoException
    extends TlsException
{
    public TlsCryptoException(String msg)
    {
        super(msg, null);
    }

    public TlsCryptoException(String msg, Throwable cause)
    {
        super(msg, cause);
    }
}
