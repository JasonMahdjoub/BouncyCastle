package org.bouncycastle.bcjcajce;

import java.security.cert.CRL;
import java.util.Collection;

import org.bouncycastle.bcutil.Selector;
import org.bouncycastle.bcutil.Store;
import org.bouncycastle.bcutil.StoreException;

/**
 * Generic interface for a PKIX based CRL store.
 *
 * @param <T> the CRL type.
 */
public interface PKIXCRLStore<T extends CRL>
    extends Store<T>
{
    /**
     * Return the matches associated with the passed in selector.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matches with the selector, an empty selector if there are none.
     * @throws StoreException in the event of an issue doing a match.
     */
    Collection<T> getMatches(Selector<T> selector)
        throws StoreException;
}
