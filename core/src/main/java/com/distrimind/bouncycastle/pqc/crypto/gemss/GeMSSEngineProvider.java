package com.distrimind.bouncycastle.pqc.crypto.gemss;

public interface GeMSSEngineProvider
{
    GeMSSEngine get();

    int getN();
}
