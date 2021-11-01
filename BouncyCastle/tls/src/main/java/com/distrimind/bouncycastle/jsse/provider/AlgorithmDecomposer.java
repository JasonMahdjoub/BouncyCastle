package com.distrimind.bouncycastle.jsse.provider;

import java.util.Set;

interface AlgorithmDecomposer
{
    Set<String> decompose(String algorithm);
}
