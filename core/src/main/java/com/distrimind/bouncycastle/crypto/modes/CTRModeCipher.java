package com.distrimind.bouncycastle.crypto.modes;

import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.MultiBlockCipher;
import com.distrimind.bouncycastle.crypto.SkippingStreamCipher;

public interface CTRModeCipher
    extends MultiBlockCipher, SkippingStreamCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
