package com.distrimind.bouncycastle.jsse.provider;

import javax.net.ssl.SSLSession;

interface ImportSSLSession
{
    SSLSession unwrap();
}
