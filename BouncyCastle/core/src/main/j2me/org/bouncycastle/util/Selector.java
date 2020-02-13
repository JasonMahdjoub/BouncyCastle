package org.bouncycastle.bcutil;

public interface Selector
{
    boolean match(Object obj);

    Object clone();
}
