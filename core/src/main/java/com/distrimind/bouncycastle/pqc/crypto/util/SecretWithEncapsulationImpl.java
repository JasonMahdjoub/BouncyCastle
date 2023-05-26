package com.distrimind.bouncycastle.pqc.crypto.util;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.security.auth.DestroyFailedException;

import com.distrimind.bouncycastle.crypto.SecretWithEncapsulation;
import com.distrimind.bouncycastle.util.Arrays;

public class SecretWithEncapsulationImpl
    implements SecretWithEncapsulation
{
    private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);

    private final byte[] sessionKey;
    private final byte[] cipher_text;

    public SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
    {
        this.sessionKey = sessionKey;
        this.cipher_text = cipher_text;
    }

    public byte[] getSecret()
    {
        byte[] clone = Arrays.clone(sessionKey);

        checkDestroyed();

        return clone;
    }

    public byte[] getEncapsulation()
    {
        byte[] clone = Arrays.clone(cipher_text);

        checkDestroyed();

        return clone;
    }

    public void destroy()
        throws DestroyFailedException
    {
        if (!hasBeenDestroyed.getAndSet(true))
        {
            Arrays.clear(sessionKey);
            Arrays.clear(cipher_text);
        }
    }

    public boolean isDestroyed()
    {
        return hasBeenDestroyed.get();
    }

    void checkDestroyed()
    {
        if (isDestroyed())
        {
            throw new IllegalStateException("data has been destroyed");
        }
    }
}
