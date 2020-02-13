package org.bouncycastle.jcajce;

import java.security.cert.Certificate;
import java.util.Collection;

import org.bouncycastle.bcutil.Selector;
import org.bouncycastle.bcutil.Store;
import org.bouncycastle.bcutil.StoreException;

public interface PKIXCertStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
