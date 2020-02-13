package org.bouncycastle.bccrypto.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.bccrypto.Digest;

class DigestInputBuffer extends ByteArrayOutputStream
{
    void updateDigest(Digest d)
    {
        d.update(this.buf, 0, count);
    }
}
