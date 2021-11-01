package com.distrimind.bouncycastle.jsse.provider;

import com.distrimind.bouncycastle.jsse.BCExtendedSSLSession;

interface ExportSSLSession
{
    BCExtendedSSLSession unwrap();
}
