package com.distrimind.bouncycastle.jsse.provider;

import com.distrimind.bouncycastle.jsse.BCX509ExtendedTrustManager;

interface ExportX509TrustManager
{
    BCX509ExtendedTrustManager unwrap();
}
