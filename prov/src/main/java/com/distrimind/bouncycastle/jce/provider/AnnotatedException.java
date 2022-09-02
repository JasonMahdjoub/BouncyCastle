package com.distrimind.bouncycastle.jce.provider;

import com.distrimind.bouncycastle.jce.exception.ExtException;

public class AnnotatedException
    extends Exception
    implements ExtException
{
    private Throwable _underlyingException;

    public AnnotatedException(String string, Throwable e)
    {
        super(string);

        _underlyingException = e;
    }

    public AnnotatedException(String string)
    {
        this(string, null);
    }

    Throwable getUnderlyingException()
    {
        return _underlyingException;
    }

    public Throwable getCause()
    {
        return _underlyingException;
    }
}
