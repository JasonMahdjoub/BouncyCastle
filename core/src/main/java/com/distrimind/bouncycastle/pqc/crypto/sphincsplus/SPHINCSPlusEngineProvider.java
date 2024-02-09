package com.distrimind.bouncycastle.pqc.crypto.sphincsplus;

interface SPHINCSPlusEngineProvider
{
    int getN();

    SPHINCSPlusEngine get();
}
