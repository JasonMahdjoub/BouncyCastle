package com.distrimind.bouncycastle.crypto;

import com.distrimind.bouncycastle.crypto.digests.EncodableDigest;
import com.distrimind.bouncycastle.util.Memoable;

/**
 * Extended digest which provides the ability to store state and
 * provide an encoding.
 */
public interface SavableDigest
    extends ExtendedDigest, EncodableDigest, Memoable
{
}
