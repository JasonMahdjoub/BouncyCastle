package org.bouncycastle.bcjcajce;

import java.security.cert.CRL;
import java.util.Collection;

import org.bouncycastle.bcutil.Selector;
import org.bouncycastle.bcutil.Store;
import org.bouncycastle.bcutil.StoreException;

public interface PKIXCRLStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
