package com.distrimind.bouncycastle.jce.provider;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.distrimind.bouncycastle.jce.X509LDAPCertStoreParameters;
import com.distrimind.bouncycastle.util.Selector;
import com.distrimind.bouncycastle.util.StoreException;
import com.distrimind.bouncycastle.x509.X509CertPairStoreSelector;
import com.distrimind.bouncycastle.x509.X509CertStoreSelector;
import com.distrimind.bouncycastle.x509.X509CertificatePair;
import com.distrimind.bouncycastle.x509.X509StoreParameters;
import com.distrimind.bouncycastle.x509.X509StoreSpi;
import com.distrimind.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * A SPI implementation of Bouncy Castle <code>X509Store</code> for getting
 * certificates form a LDAP directory.
 *
 * @see com.distrimind.bouncycastle.x509.X509Store
 */
public class X509StoreLDAPCerts
    extends X509StoreSpi
{

    private LDAPStoreHelper helper;

    public X509StoreLDAPCerts()
    {
    }

    /**
     * Initializes this LDAP cert store implementation.
     *
     * @param params <code>X509LDAPCertStoreParameters</code>.
     * @throws IllegalArgumentException if <code>params</code> is not an instance of
     *                                  <code>X509LDAPCertStoreParameters</code>.
     */
    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509LDAPCertStoreParameters))
        {
            throw new IllegalArgumentException(
                "Initialization parameters must be an instance of "
                    + X509LDAPCertStoreParameters.class.getName() + ".");
        }
        helper = new LDAPStoreHelper((X509LDAPCertStoreParameters)params);
    }

    /**
     * Returns a collection of matching certificates from the LDAP location.
     * <p>
     * The selector must be a of type <code>X509CertStoreSelector</code>. If
     * it is not an empty collection is returned.
     * </p><p>
     * The implementation searches only for CA certificates, if the method
     * {@link java.security.cert.X509CertSelector#getBasicConstraints()} is
     * greater or equal to 0. If it is -2 only end certificates are searched.
     * </p><p>
     * The subject and the serial number for end certificates should be
     * reasonable criterias for a selector.
     * </p>
     * @param selector The selector to use for finding.
     * @return A collection with the matches.
     * @throws StoreException if an exception occurs while searching.
     */
    public Collection engineGetMatches(Selector selector) throws StoreException
    {
        if (!(selector instanceof X509CertStoreSelector))
        {
            return Collections.EMPTY_SET;
        }
        X509CertStoreSelector xselector = (X509CertStoreSelector)selector;
        Set set = new HashSet();
        // test if only CA certificates should be selected
        if (xselector.getBasicConstraints() > 0)
        {
            set.addAll(helper.getCACertificates(xselector));
            set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
        }
        // only end certificates should be selected
        else if (xselector.getBasicConstraints() == -2)
        {
            set.addAll(helper.getUserCertificates(xselector));
        }
        // nothing specified
        else
        {
            set.addAll(helper.getUserCertificates(xselector));
            set.addAll(helper.getCACertificates(xselector));
            set.addAll(getCertificatesFromCrossCertificatePairs(xselector));
        }
        return set;
    }

    private Collection getCertificatesFromCrossCertificatePairs(
        X509CertStoreSelector xselector) throws StoreException
    {
        Set set = new HashSet();
        X509CertPairStoreSelector ps = new X509CertPairStoreSelector();

        ps.setForwardSelector(xselector);
        ps.setReverseSelector(new X509CertStoreSelector());
        
        Set crossCerts = new HashSet(helper.getCrossCertificatePairs(ps));
        Set forward = new HashSet();
        Set reverse = new HashSet();
        Iterator it = crossCerts.iterator();
        while (it.hasNext())
        {
            X509CertificatePair pair = (X509CertificatePair)it.next();
            if (pair.getForward() != null)
            {
                forward.add(pair.getForward());
            }
            if (pair.getReverse() != null)
            {
                reverse.add(pair.getReverse());
            }
        }
        set.addAll(forward);
        set.addAll(reverse);
        return set;
    }
}
