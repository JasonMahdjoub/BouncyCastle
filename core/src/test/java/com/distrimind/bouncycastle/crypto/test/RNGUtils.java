package com.distrimind.bouncycastle.crypto.test;

import java.util.Random;

class RNGUtils
{
    public static int nextInt(Random rng, int n)
    {
        return rng.nextInt(n);
    }
}
