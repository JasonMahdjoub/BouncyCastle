package com.distrimind.bouncycastle.jce.provider.test.nist;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import com.distrimind.bouncycastle.asn1.ASN1Encoding;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.x509.X509Extension;
import com.distrimind.bouncycastle.i18n.ErrorBundle;
import com.distrimind.bouncycastle.test.PrintTestResult;
import com.distrimind.bouncycastle.test.TestResourceFinder;
import com.distrimind.bouncycastle.util.Strings;
import com.distrimind.bouncycastle.util.encoders.Base64;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.x509.PKIXCertPathReviewer;
import com.distrimind.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * NIST CertPath test data for RFC 3280
 */
public class NistCertPathReviewerTest
    extends TestCase
{
    private static final String NNBSP = Strings.fromUTF8ByteArray(Hex.decode("e280af"));

    private static final String GOOD_CA_CERT = "GoodCACert";

    private static final String GOOD_CA_CRL = "GoodCACRL";

    private static final String TRUST_ANCHOR_ROOT_CRL = "TrustAnchorRootCRL";

    private static final String TRUST_ANCHOR_ROOT_CERTIFICATE = "TrustAnchorRootCertificate";

    private static final char[] PKCS12_PASSWORD = "password".toCharArray();
    
    private static String NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
    private static String NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
    private static String NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";
    
    private static Map   certs = new HashMap();
    private static Map   crls = new HashMap();
    
    private static Set   noPolicies = Collections.EMPTY_SET;
    private static Set   nistTestPolicy1 = Collections.singleton(NIST_TEST_POLICY_1);
    private static Set   nistTestPolicy2 = Collections.singleton(NIST_TEST_POLICY_2);
    private static Set   nistTestPolicy3 = Collections.singleton(NIST_TEST_POLICY_3);
    private static Set   nistTestPolicy1And2 = new HashSet(Arrays.asList(new String[] { NIST_TEST_POLICY_1, NIST_TEST_POLICY_2 }));
        
    public void testValidSignaturesTest1()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "ValidCertificatePathTest1EE", GOOD_CA_CERT}, 
                new String[] { GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL });
    }
    
    public void testInvalidCASignatureTest2()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "ValidCertificatePathTest1EE", "BadSignedCACert" }, 
                new String[] { "BadSignedCACRL", TRUST_ANCHOR_ROOT_CRL},
                1,
                "CertPathReviewer.signatureNotVerified",
                "The certificate signature is invalid. A java.security.SignatureException occurred.");
    }
    
    public void testInvalidEESignatureTest3()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
            new String[] { GOOD_CA_CERT, "InvalidEESignatureTest3EE" }, 
            new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
            0,
            "CertPathReviewer.signatureNotVerified",
            "The certificate signature is invalid. A java.security.SignatureException occurred.");
    }
    
    public void testValidDSASignaturesTest4()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "ValidDSASignaturesTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL" });
    }
    /*
    public void testValidDSAParameterInheritanceTest5()
        throws Exception
    {
        doTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "DSAParametersInheritedCACert", "ValidDSAParameterInheritanceTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL", "DSAParametersInheritedCACRL" });
    }
    */
    public void testInvalidDSASignaturesTest6()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "DSACACert", "InvalidDSASignatureTest6EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "DSACACRL" },
                0,
                "CertPathReviewer.signatureNotVerified",
                "The certificate signature is invalid. A java.security.SignatureException occurred.");
    }
    
    public void testCANotBeforeDateTest1()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "BadnotBeforeDateCACert", "InvalidCAnotBeforeDateTest1EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "BadnotBeforeDateCACRL" },
                1,
                "CertPathReviewer.certificateNotYetValid",
                "Could not validate the certificate. Certificate is not valid until Jan 1, 2047 12:01:00 PM GMT.");
    }
    
    public void testInvalidEENotBeforeDateTest2()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "InvalidEEnotBeforeDateTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "CertPathReviewer.certificateNotYetValid",
                "Could not validate the certificate. Certificate is not valid until Jan 1, 2047 12:01:00 PM GMT.");
    }
    
    public void testValidPre2000UTCNotBeforeDateTest3()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "Validpre2000UTCnotBeforeDateTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL });
    }
    
    public void testValidGeneralizedTimeNotBeforeDateTest4()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "ValidGeneralizedTimenotBeforeDateTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL });
    }
    
    public void testInvalidCANotAfterDateTest5()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "BadnotAfterDateCACert", "InvalidCAnotAfterDateTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "BadnotAfterDateCACRL" },
                1,
                "CertPathReviewer.certificateExpired",
                "Could not validate the certificate. Certificate expired on Jan 1, 2002 12:01:00 PM GMT.");
    }
    
    public void testInvalidEENotAfterDateTest6()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "InvalidEEnotAfterDateTest6EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "CertPathReviewer.certificateExpired",
                "Could not validate the certificate. Certificate expired on Jan 1, 2002 12:01:00 PM GMT.");
    }
    
    public void testInvalidValidPre2000UTCNotAfterDateTest7()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "Invalidpre2000UTCEEnotAfterDateTest7EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL },
                0,
                "CertPathReviewer.certificateExpired",
                "Could not validate the certificate. Certificate expired on Jan 1, 1999 12:01:00 PM GMT.");
    }
    
    public void testInvalidNegativeSerialNumberTest15()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NegativeSerialNumberCACert", "InvalidNegativeSerialNumberTest15EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NegativeSerialNumberCACRL" },
                0,
                "CertPathReviewer.certRevoked",
                "The certificate was revoked at Apr 19, 2001 2:57:20 PM GMT. Reason: Key Compromise.");
    }
    
    //
    // 4.8 Certificate Policies
    //
    public void testAllCertificatesSamePolicyTest1()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "ValidCertificatePathTest1EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                noPolicies); 
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy1);
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                certList, 
                crlList,
                nistTestPolicy1And2);
    }
    
    public void testAllCertificatesNoPoliciesTest2()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL" });
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { "NoPoliciesCACert", "AllCertificatesNoPoliciesTest2EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, "NoPoliciesCACRL" },
                noPolicies,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest3()
        throws Exception
    {
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" });
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" },
                noPolicies,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCACert", "DifferentPoliciesTest3EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCACRL" },
                nistTestPolicy1And2,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest4()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "GoodsubCACert", "DifferentPoliciesTest4EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "GoodsubCACRL" },
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected."); 
    }
    
    public void testDifferentPoliciesTest5()
        throws Exception
    {
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, 
                new String[] { GOOD_CA_CERT, "PoliciesP2subCA2Cert", "DifferentPoliciesTest5EE" }, 
                new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL, "PoliciesP2subCA2CRL" },
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected."); 
    }
    
    public void testOverlappingPoliciesTest6()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP1234CACert", "PoliciesP1234subCAP123Cert", "PoliciesP1234subsubCAP123P12Cert", "OverlappingPoliciesTest6EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP1234CACRL", "PoliciesP1234subCAP123CRL", "PoliciesP1234subsubCAP123P12CRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    public void testDifferentPoliciesTest7()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P1Cert", "DifferentPoliciesTest7EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP12P1CRL" };
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected."); 
    }
    
    public void testDifferentPoliciesTest8()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "PoliciesP12subCAP1Cert", "PoliciesP12subsubCAP1P2Cert", "DifferentPoliciesTest8EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL", "PoliciesP12subCAP1CRL", "PoliciesP12subsubCAP1P2CRL" };
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
    }
    
    public void testDifferentPoliciesTest9()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "PoliciesP123subCAP12Cert", "PoliciesP123subsubCAP12P2Cert", "PoliciesP123subsubsubCAP12P2P1Cert", "DifferentPoliciesTest9EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL", "PoliciesP123subCAP12CRL", "PoliciesP123subsubCAP2P2CRL", "PoliciesP123subsubsubCAP12P2P1CRL" };
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
    }
    
    public void testAllCertificatesSamePoliciesTest10()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "AllCertificatesSamePoliciesTest10EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
    }
    
    public void testAllCertificatesAnyPolicyTest11()
        throws Exception
    {
        String[] certList = new String[] { "anyPolicyCACert", "AllCertificatesanyPolicyTest11EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);

        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
    }
    
    public void testDifferentPoliciesTest12()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP3CACert", "DifferentPoliciesTest12EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP3CACRL" };
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList,
                -1,
                "CertPathReviewer.noValidPolicyTree",
                "Policy checking failed: no valid policy tree found when one expected.");
    }
    
    public void testAllCertificatesSamePoliciesTest13()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP123CACert", "AllCertificatesSamePoliciesTest13EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP123CACRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy3);
    }
    
    public void testAnyPolicyTest14()
        throws Exception
    {
        String[] certList = new String[] { "anyPolicyCACert", "AnyPolicyTest14EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "anyPolicyCACRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest15()
        throws Exception
    {
        String[] certList = new String[] { "UserNoticeQualifierTest15EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest16()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "UserNoticeQualifierTest16EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest17()
        throws Exception
    {
        String[] certList = new String[] { GOOD_CA_CERT, "UserNoticeQualifierTest17EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    public void testUserNoticeQualifierTest18()
        throws Exception
    {
        String[] certList = new String[] { "PoliciesP12CACert", "UserNoticeQualifierTest18EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL, "PoliciesP12CACRL" };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2);
    }
    
    public void testUserNoticeQualifierTest19()
        throws Exception
    {
        String[] certList = new String[] { "UserNoticeQualifierTest19EE" };
        String[] crlList = new String[] { TRUST_ANCHOR_ROOT_CRL };
        
        doAcceptingTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy1);
        doErrorTest(TRUST_ANCHOR_ROOT_CERTIFICATE, certList, crlList, nistTestPolicy2,
                -1,
                "CertPathReviewer.invalidPolicy",
                "Path processing failed on policy.");
    }
    
    private void doAcceptingTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls)
        throws Exception
    {
        PKIXCertPathReviewer result = doTest(trustAnchor,certs,crls);
        if (!result.isValidCertPath())
        {
            fail("path rejected when should be accepted");
        }
    }
    
    private void doAcceptingTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies)
        throws Exception
    {
        PKIXCertPathReviewer result = doTest(trustAnchor,certs,crls,policies);
        if (!result.isValidCertPath())
        {
            fail("path rejected when should be accepted");
        }
    }
    
    private void doErrorTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        int         index,
        String      messageId,
        String      message)
        throws Exception
    {
        PKIXCertPathReviewer result = doTest(trustAnchor, certs, crls);
        if (result.isValidCertPath()) 
        {
            fail("path accepted when should be rejected");
        }
        else
        {
            ErrorBundle msg = (ErrorBundle) result.getErrors(index).iterator().next();
            assertEquals(messageId,msg.getId());
            assertEquals(message,msg.getText(Locale.ENGLISH,TimeZone.getTimeZone("GMT")).replace("Greenwich Mean Time", "GMT").replace(NNBSP, " "));
        }
    }
    
    private void doErrorTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies,
        int         index,
        String      messageId,
        String      message)
        throws Exception
    {
        PKIXCertPathReviewer result = doTest(trustAnchor, certs, crls, policies);
        if (result.isValidCertPath()) 
        {
            fail("path accepted when should be rejected");
        }
        else
        {
            ErrorBundle msg = (ErrorBundle) result.getErrors(index).iterator().next();
            assertEquals(messageId,msg.getId());
            assertEquals(message,msg.getText(Locale.ENGLISH,TimeZone.getTimeZone("GMT")));
        }
    }
    
    private PKIXCertPathReviewer doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls)
        throws Exception
    {
        return doTest(trustAnchor, certs, crls, null);
    }
    
    private PKIXCertPathReviewer doTest(
        String      trustAnchor,
        String[]    certs,
        String[]    crls,
        Set         policies)
        throws Exception
    {
        Set  trustedSet = Collections.singleton(getTrustAnchor(trustAnchor));
        List certsAndCrls = new ArrayList();
        X509Certificate endCert = loadCert(certs[certs.length - 1]);
        
        for (int i = 0; i != certs.length - 1; i++)
        {
            certsAndCrls.add(loadCert(certs[i]));
        }
        
        certsAndCrls.add(endCert);
    
        CertPath certPath = CertificateFactory.getInstance("X.509","BC").generateCertPath(certsAndCrls);
    
        for (int i = 0; i != crls.length; i++)
        {
            certsAndCrls.add(loadCrl(crls[i]));
        }
    
        CertStore  store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certsAndCrls), "BC");
        
        //CertPathValidator validator = CertPathValidator.getInstance("PKIX","BC");
        PKIXCertPathReviewer reviewer;
        PKIXParameters    params = new PKIXParameters(trustedSet);
        
        params.addCertStore(store);
        params.setRevocationEnabled(true);
        params.setDate(new GregorianCalendar(2010, 1, 1).getTime());

        if (policies != null)
        {
            params.setExplicitPolicyRequired(true);
            params.setInitialPolicies(policies);
        }
        
        reviewer = new PKIXCertPathReviewer(certPath,params);
        
        return reviewer;
    }

    private X509Certificate loadCert(
        String certName)
    {
        X509Certificate cert = (X509Certificate)certs.get(certName);
        
        if (cert != null)
        {
            return cert;
        }
        
        try
        {
            InputStream in = TestResourceFinder.findTestResource("PKITS/certs/", certName + ".crt");
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            cert = (X509Certificate)fact.generateCertificate(in);
    
            certs.put(certName, cert);
            
            return cert;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading certificate " + certName + ": " + e);
        }
    }
    
    private X509CRL loadCrl(
        String crlName)
        throws Exception
    {
        X509CRL crl = (X509CRL)certs.get(crlName);
        
        if (crl != null)
        {
            return crl;
        }
        
        try
        {
            InputStream in = TestResourceFinder.findTestResource("PKITS/crls/", crlName + ".crl");
            
            CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
            
            crl = (X509CRL)fact.generateCRL(in);
            
            crls.put(crlName, crl);
            
            return crl;
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception loading CRL: " + crlName);
        }
    }

    private TrustAnchor getTrustAnchor(String trustAnchorName)
        throws Exception
    {
        X509Certificate cert = loadCert(trustAnchorName);
        byte[]          extBytes = cert.getExtensionValue(X509Extension.nameConstraints.getId());
        
        if (extBytes != null)
        {
            ASN1Primitive extValue = X509ExtensionUtil.fromExtensionValue(extBytes);
            
            return new TrustAnchor(cert, extValue.getEncoded(ASN1Encoding.DER));
        }
        
        return new TrustAnchor(cert, null);
    }

    // extended key usage chain
       static byte[] extEE = Base64.decode("MIICtDCCAh2gAwIBAgIBAzANBgkqhkiG9w0BAQUFADCBkjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxKDAmBgNVBAsMH0JvdW5jeSBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMB4XDTE1MDMyNDAzNTEwOVoXDTE1MDUyMzAzNTEwOVowgZYxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMRIwEAYDVQQHDAlNZWxib3VybmUxGDAWBgNVBAMMD0VyaWMgSC4gRWNoaWRuYTEvMC0GCSqGSIb3DQEJARYgZmVlZGJhY2stY3J5cHRvQGJvdW5jeWNhc3RsZS5vcmcwWjANBgkqhkiG9w0BAQEFAANJADBGAkEAtKfkYXBXTxapcIKyK+WLaipil5hBm+EocqS9umJs+umQD3ar+xITnc5d5WVk+rK2VDFloEDGBoh0IOM9ke1+1wIBEaNaMFgwHQYDVR0OBBYEFNBs7G01g7xVEhsMyz7+1yamFmRoMB8GA1UdIwQYMBaAFJQIM28yQPeHN9rRIKrtLqduyckeMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMA0GCSqGSIb3DQEBBQUAA4GBAICrsNswvaXFMreUHHRHrhU4QqPOds8XJe0INx3v/5TfyjPPDMihMEm8WtWbVpFgFAqUQoZscf8cE/SO5375unYFgxrK+p2/je9E82VLF4Xb0cWizjQoWvvTmvFYjt43cGGXgySFLTrW87ju9uNFr/l4W9xvI0hoLI96vEW7Ccho");
       static byte[] extCA = Base64.decode("MIIDIzCCAoygAwIBAgIBAjANBgkqhkiG9w0BAQUFADBcMQswCQYDVQQGEwJBVTEoMCYGA1UECgwfVGhlIExlZ2lvbiBvZiB0aGUgQm91bmN5IENhc3RsZTEjMCEGA1UECwwaQm91bmN5IFByaW1hcnkgQ2VydGlmaWNhdGUwHhcNMTUwMzI0MDM1MTA5WhcNMTUwNTIzMDM1MTA5WjCBkjELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxKDAmBgNVBAsMH0JvdW5jeSBJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUxLzAtBgkqhkiG9w0BCQEWIGZlZWRiYWNrLWNyeXB0b0Bib3VuY3ljYXN0bGUub3JnMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCN4NETxec2lpyNKwR6JD+P4Y7a1kzenoQtNmkjDKSG98/d4fjuxU0ZBf/wSsyF5hCT4YDK3GzqQH8ZPUS7DpRJuNu0l4TNnjYmDDngapRymZeMbtgwByTohxmM/t4g8/veZY+ivQeL6Uajkr00nytJxIbiDEBViOMGcGyQFzCOaQIDAP//o4G9MIG6MB0GA1UdDgQWBBSUCDNvMkD3hzfa0SCq7S6nbsnJHjCBhAYDVR0jBH0we4AUwDYZB63EiJeoXnJvawnr5ebxKVyhYKReMFwxCzAJBgNVBAYTAkFVMSgwJgYDVQQKDB9UaGUgTGVnaW9uIG9mIHRoZSBCb3VuY3kgQ2FzdGxlMSMwIQYDVQQLDBpCb3VuY3kgUHJpbWFyeSBDZXJ0aWZpY2F0ZYIBATASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBBQUAA4GBAJqUlDjse7Og+7qkkFsiXHzQ8FxT82hzfcji8W7bPwZddCPBEluxCJiJBPYXWsLvwo6BEmCDzT9lLQZ+QZyL1fVbOVHiI24hAalbEBEIrEO4GXMD9spqRQ5yoTJ8CgZHTPo0rJkH/ebprp0YHtahVF440zBOvuLM0QTYpERgO2Oe");
       static byte[] extTrust = Base64.decode("MIICJTCCAY4CAQEwDQYJKoZIhvcNAQEFBQAwXDELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMB4XDTE1MDMyNDAzNTEwOVoXDTE1MDUyMzAzNTEwOVowXDELMAkGA1UEBhMCQVUxKDAmBgNVBAoMH1RoZSBMZWdpb24gb2YgdGhlIEJvdW5jeSBDYXN0bGUxIzAhBgNVBAsMGkJvdW5jeSBQcmltYXJ5IENlcnRpZmljYXRlMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCyWdLW5ienaMlL42Fkwtn8edl6q5JTFA5b8XdRGXcx1vdUDSUJ57n/7gpwpuJtVuktLt1/hauoVgC2kInzX2vb88KY4FhCU12fBk5rA5HLfTBuCi0gxN+057SalkC96ibBCtacPwUAfOJRPO5Ez+AZmOYrbDY30/wDkQebJu421QIBETANBgkqhkiG9w0BAQUFAAOBgQCDNfqQnQbbmnGzZTl7ccWIyw7SPzWnijpKsQpuRNGkoXfkCcuQLZudytEFZGEL0cycNBnierjJWAn78zGpCQtab01r1GwytRMYz8qO5IIrhsJ4XNafNypYZbi0WtPa07UCQp8tipMbfQNLzSkvkIAaD5IfhdaWKLrSQJwmGg7YAg==");

       public void testValidateWithExtendedKeyUsage()
           throws Exception
       {
           CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
   
           X509Certificate rootCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extTrust));
           X509Certificate interCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extCA));
           X509Certificate finalCert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(extEE));

           List list = new ArrayList();
           list.add(rootCert);
           list.add(interCert);
           list.add(finalCert);

           CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
           CertStore store = CertStore.getInstance("Collection", ccsp, "BC");
           Date validDate = new Date(rootCert.getNotBefore().getTime() + 60 * 60 * 1000);
           //validating path
           List certchain = new ArrayList();
           certchain.add(finalCert);
           certchain.add(interCert);
           CertPath cp = CertificateFactory.getInstance("X.509", "BC").generateCertPath(certchain);
           Set trust = new HashSet();
           trust.add(new TrustAnchor(rootCert, null));

           PKIXParameters param = new PKIXParameters(trust);
           param.addCertStore(store);
           param.setDate(validDate);
           param.setRevocationEnabled(false);

           PKIXCertPathReviewer result = new PKIXCertPathReviewer(cp,param);

           assertTrue(result.isValidCertPath());
       }

    public static void main (String[] args) 
        throws Exception
    {   
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
    
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("NIST CertPath Tests");
        
        suite.addTestSuite(NistCertPathReviewerTest.class);
        
        return suite;
    }
}
