package com.distrimind.bouncycastle.util;

public interface Selector
{
    boolean match(Object obj);

    Object clone();
}
