package com.distrimind.bouncycastle.pqc.legacy.crypto.gmss;

import com.distrimind.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
