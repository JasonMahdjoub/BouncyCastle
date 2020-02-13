package org.bouncycastle.bccrypto.tls;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.bccrypto.Signer;

class SignerInputBuffer extends ByteArrayOutputStream
{
    void updateSigner(Signer s)
    {
        s.update(this.buf, 0, count);
    }
}