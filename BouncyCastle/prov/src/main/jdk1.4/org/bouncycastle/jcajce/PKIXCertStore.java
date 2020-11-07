package com.distrimind.bouncycastle.jcajce;

import java.security.cert.Certificate;
import java.util.Collection;

import com.distrimind.bouncycastle.util.Selector;
import com.distrimind.bouncycastle.util.Store;
import com.distrimind.bouncycastle.util.StoreException;

public interface PKIXCertStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
