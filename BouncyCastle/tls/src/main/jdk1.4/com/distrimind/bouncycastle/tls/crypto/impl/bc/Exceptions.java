package com.distrimind.bouncycastle.tls.crypto.impl.bc;

class Exceptions
{
    static IllegalArgumentException illegalArgumentException(String message, Throwable cause)
    {
        return new com.distrimind.bouncycastle.tls.exception.IllegalArgumentException(message, cause);
    }
}
