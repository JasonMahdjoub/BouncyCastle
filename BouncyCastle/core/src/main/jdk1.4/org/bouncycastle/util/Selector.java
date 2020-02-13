package org.bouncycastle.bcutil;

public interface Selector
    extends Cloneable
{
    boolean match(Object obj);

    Object clone();
}
