package com.distrimind.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

public interface SPHINCSKey
    extends Key
{
    byte[] getKeyData();
}
