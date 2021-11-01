package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

class Exceptions
{
    static IllegalStateException illegalStateException(String message, Throwable cause)
    {
        return new com.distrimind.bouncycastle.tls.exception.IllegalStateException(message, cause);
    }

    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new com.distrimind.bouncycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
