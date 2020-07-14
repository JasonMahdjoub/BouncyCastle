package com.distrimind.bouncycastle.tls;

import java.io.IOException;

public interface TlsCloseable
{
    public void close() throws IOException;
}
