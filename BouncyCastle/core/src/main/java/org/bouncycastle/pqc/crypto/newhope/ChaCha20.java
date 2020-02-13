package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.bccrypto.engines.ChaChaEngine;
import org.bouncycastle.bccrypto.params.KeyParameter;
import org.bouncycastle.bccrypto.params.ParametersWithIV;

class ChaCha20
{
    static void process(byte[] key, byte[] nonce, byte[] buf, int off, int len)
    {
        ChaChaEngine e = new ChaChaEngine(20);
        e.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        e.processBytes(buf, off, len, buf, off);
    }
}
