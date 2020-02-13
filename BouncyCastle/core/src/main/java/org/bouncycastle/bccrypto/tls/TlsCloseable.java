package org.bouncycastle.bccrypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsCloseable
{
    public void close() throws IOException;
}
