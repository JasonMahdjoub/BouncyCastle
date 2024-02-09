package com.distrimind.bouncycastle.crypto.modes;

import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.MultiBlockCipher;

public interface CBCModeCipher
    extends MultiBlockCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
