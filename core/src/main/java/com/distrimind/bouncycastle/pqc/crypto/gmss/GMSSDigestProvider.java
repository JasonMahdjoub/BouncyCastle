package com.distrimind.bouncycastle.pqc.crypto.gmss;

import com.distrimind.bouncycastle.crypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
