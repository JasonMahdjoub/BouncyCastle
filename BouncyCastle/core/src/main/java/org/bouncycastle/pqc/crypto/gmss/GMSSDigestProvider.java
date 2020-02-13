package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.bccrypto.Digest;

public interface GMSSDigestProvider
{
    Digest get();
}
