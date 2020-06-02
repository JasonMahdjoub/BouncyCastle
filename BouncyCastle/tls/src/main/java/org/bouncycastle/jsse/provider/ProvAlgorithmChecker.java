package org.bouncycastle.jsse.provider;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.bcasn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.bcasn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.bcasn1.x509.KeyPurposeId;
import org.bouncycastle.bcasn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.bcjcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.bcutil.Arrays;

class ProvAlgorithmChecker
    extends PKIXCertPathChecker
{
    static final int KU_DIGITAL_SIGNATURE = 0;
    static final int KU_KEY_ENCIPHERMENT = 2;
    static final int KU_KEY_AGREEMENT = 4;

    private static final Map<String, String> sigAlgNames = createSigAlgNames();
    private static final Set<String> sigAlgNoParams = createSigAlgNoParams();

    private static final byte[] DER_NULL_ENCODING = new byte[]{ 0x05, 0x00 };

    private static Map<String, String> createSigAlgNames()
    {
        Map<String, String> names = new HashMap<String, String>();

        // TODO[jsse] We may need more mappings (from sigAlgOID) here for SunJSSE compatibility (e.g. RSASSA-PSS?)
        names.put(EdECObjectIdentifiers.id_Ed25519.getId(), "Ed25519");
        names.put(EdECObjectIdentifiers.id_Ed448.getId(), "Ed448");
        names.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "SHA1withDSA");
        names.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");

        return Collections.unmodifiableMap(names);
    }

    private static Set<String> createSigAlgNoParams()
    {
        Set<String> noParams = new HashSet<String>();

        noParams.add(OIWObjectIdentifiers.dsaWithSHA1.getId());
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1.getId());

        return Collections.unmodifiableSet(noParams);
    }

    private final JcaJceHelper helper;
    private final BCAlgorithmConstraints algorithmConstraints;

    private X509Certificate issuerCert;

    ProvAlgorithmChecker(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints)
    {
        if (null == helper)
        {
            throw new NullPointerException("'helper' cannot be null");
        }
        if (null == algorithmConstraints)
        {
            throw new NullPointerException("'algorithmConstraints' cannot be null");
        }

        this.helper = helper;
        this.algorithmConstraints = algorithmConstraints;

        this.issuerCert = null;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException
    {
        if (forward)
        {
            throw new CertPathValidatorException("forward checking not supported");
        }

        this.issuerCert = null;
    }

    @Override
    public boolean isForwardCheckingSupported()
    {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions()
    {
        return null;
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException
    {
        if (!(cert instanceof X509Certificate))
        {
            throw new CertPathValidatorException("checker can only be used for X.509 certificates");
        }

        X509Certificate subjectCert = (X509Certificate)cert;

        if (null == issuerCert)
        {
            // NOTE: This would be redundant with the 'taCert' check in 'checkCertPathExtras'
            //checkIssued(helper, algorithmConstraints, subjectCert);
        }
        else
        {
            checkIssuedBy(helper, algorithmConstraints, subjectCert, issuerCert);
        }

        this.issuerCert = subjectCert;
    }

    static void checkCertPathExtras(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException
    {
        X509Certificate taCert = chain[chain.length - 1];

        if (chain.length > 1)
        {
            checkIssuedBy(helper, algorithmConstraints, chain[chain.length - 2], taCert);
        }

        X509Certificate eeCert = chain[0];

        checkEndEntity(helper, algorithmConstraints, eeCert, ekuOID, kuBit);
    }

    static void checkChain(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        Set<X509Certificate> trustedCerts, X509Certificate[] chain, KeyPurposeId ekuOID, int kuBit)
        throws CertPathValidatorException
    {
        int taPos = chain.length;
        while (taPos > 0 && trustedCerts.contains(chain[taPos - 1]))
        {
            --taPos;
        }

        if (taPos < chain.length)
        {
            X509Certificate taCert = chain[taPos];

            if (taPos > 0)
            {
                checkIssuedBy(helper, algorithmConstraints, chain[taPos - 1], taCert);
            }
        }
        else
        {
            checkIssued(helper, algorithmConstraints, chain[taPos - 1]);
        }

        ProvAlgorithmChecker algorithmChecker = new ProvAlgorithmChecker(helper, algorithmConstraints);
        algorithmChecker.init(false);

        for (int i = taPos - 1; i >= 0; --i)
        {
            algorithmChecker.check(chain[i]);
        }

        X509Certificate eeCert = chain[0];

        checkEndEntity(helper, algorithmConstraints, eeCert, ekuOID, kuBit);
    }

    private static void checkEndEntity(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate eeCert, KeyPurposeId ekuOID, int kuBit) throws CertPathValidatorException
    {
        if (null != ekuOID)
        {
            if (!supportsExtendedKeyUsage(eeCert, ekuOID))
            {
                throw new CertPathValidatorException(
                    "Certificate doesn't support '" + getExtendedKeyUsageName(ekuOID) + "' ExtendedKeyUsage");
            }
        }

        if (kuBit >= 0)
        {
            if (!supportsKeyUsage(eeCert, kuBit))
            {
                throw new CertPathValidatorException(
                    "Certificate doesn't support '" + getKeyUsageName(kuBit) + "' KeyUsage");
            }

            if (!algorithmConstraints.permits(getKeyUsagePrimitives(kuBit), eeCert.getPublicKey()))
            {
                throw new CertPathValidatorException(
                    "Public key not permitted for '" + getKeyUsageName(kuBit) + "' KeyUsage");
            }
        }
    }

    private static void checkIssued(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate cert) throws CertPathValidatorException
    {
        String sigAlgName = getSigAlgName(cert);
        AlgorithmParameters sigAlgParams = getSigAlgParams(helper, cert);

        if (!algorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName, sigAlgParams))
        {
            throw new CertPathValidatorException();
        }
    }

    private static void checkIssuedBy(JcaJceHelper helper, BCAlgorithmConstraints algorithmConstraints,
        X509Certificate subjectCert, X509Certificate issuerCert) throws CertPathValidatorException
    {
        String sigAlgName = getSigAlgName(subjectCert);
        AlgorithmParameters sigAlgParams = getSigAlgParams(helper, subjectCert);

        if (!algorithmConstraints.permits(JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC, sigAlgName,
            issuerCert.getPublicKey(), sigAlgParams))
        {
            throw new CertPathValidatorException();
        }
    }

    static String getExtendedKeyUsageName(KeyPurposeId ekuOID)
    {
        if (KeyPurposeId.id_kp_clientAuth.equals(ekuOID))
        {
            return "clientAuth";
        }
        if (KeyPurposeId.id_kp_serverAuth.equals(ekuOID))
        {
            return "serverAuth";
        }
        return "(" + ekuOID + ")";
    }

    static String getKeyUsageName(int kuBit)
    {
        switch (kuBit)
        {
        case KU_DIGITAL_SIGNATURE:
            return "digitalSignature";
        case KU_KEY_ENCIPHERMENT:
            return "keyEncipherment";
        case KU_KEY_AGREEMENT:
            return "keyAgreement";
        default:
            return "(" + kuBit + ")";
        }
    }

    static Set<BCCryptoPrimitive> getKeyUsagePrimitives(int kuBit)
    {
        switch (kuBit)
        {
        case KU_KEY_AGREEMENT:
            return JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        case KU_KEY_ENCIPHERMENT:
            return JsseUtils.KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
        default:
            return JsseUtils.SIGNATURE_CRYPTO_PRIMITIVES_BC;
        }
    }

    static String getSigAlgName(X509Certificate cert)
    {
        String sigAlgName = sigAlgNames.get(cert.getSigAlgOID());
        if (null != sigAlgName)
        {
            return sigAlgName;
        }

        return cert.getSigAlgName();
    }

    static AlgorithmParameters getSigAlgParams(JcaJceHelper helper, X509Certificate cert)
        throws CertPathValidatorException
    {
        byte[] encoded = cert.getSigAlgParams();
        if (null == encoded)
        {
            return null;
        }

        String sigAlgOID = cert.getSigAlgOID();
        if (sigAlgNoParams.contains(sigAlgOID) && Arrays.areEqual(DER_NULL_ENCODING, encoded))
        {
            return null;
        }

        AlgorithmParameters sigAlgParams;
        try
        {
            sigAlgParams = helper.createAlgorithmParameters(sigAlgOID);
        }
        catch (GeneralSecurityException e)
        {
            // TODO[jsse] Consider requiring 'encoded' to be DER_NULL_ENCODING here
            return null;
        }

        try
        {
            sigAlgParams.init(encoded);
        }
        catch (Exception e)
        {
            throw new CertPathValidatorException(e);
        }

        return sigAlgParams;
    }

    static boolean permitsKeyUsage(PublicKey publicKey, boolean[] ku, int kuBit, BCAlgorithmConstraints algorithmConstraints)
    {
        return supportsKeyUsage(ku, kuBit)
            && algorithmConstraints.permits(getKeyUsagePrimitives(kuBit), publicKey);
    }

    static boolean supportsExtendedKeyUsage(X509Certificate cert, KeyPurposeId ekuOID)
    {
        try
        {
            return supportsExtendedKeyUsage(cert.getExtendedKeyUsage(), ekuOID);
        }
        catch (CertificateParsingException e)
        {
            return false;
        }
    }

    static boolean supportsExtendedKeyUsage(List<String> eku, KeyPurposeId ekuOID)
    {
        return null == eku
            || eku.contains(ekuOID.getId())
            || eku.contains(KeyPurposeId.anyExtendedKeyUsage.getId());
    }

    static boolean supportsKeyUsage(X509Certificate cert, int kuBit)
    {
        return supportsKeyUsage(cert.getKeyUsage(), kuBit);
    }

    static boolean supportsKeyUsage(boolean[] ku, int kuBit)
    {
        return null == ku || (ku.length > kuBit && ku[kuBit]);
    }
}
