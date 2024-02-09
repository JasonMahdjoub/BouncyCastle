package com.distrimind.bouncycastle.cert.cmp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.asn1.cmp.CMPCertificate;
import com.distrimind.bouncycastle.asn1.cmp.CertConfirmContent;
import com.distrimind.bouncycastle.asn1.cmp.CertStatus;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import com.distrimind.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;

/**
 * Builder class for a {@link CertConfirmContent} message.
 */
public class CertificateConfirmationContentBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private List<CMPCertificate> acceptedCerts = new ArrayList<CMPCertificate>();
    private List<AlgorithmIdentifier> acceptedSignatureAlgorithms = new ArrayList<AlgorithmIdentifier>();
    private List<ASN1Integer> acceptedReqIds = new ArrayList<ASN1Integer>();

    public CertificateConfirmationContentBuilder()
    {
        this(new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContentBuilder(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
    }
    
    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, BigInteger certReqID)
    {
        return addAcceptedCertificate(certHolder, new ASN1Integer(certReqID));
    }

    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, ASN1Integer certReqID)
    {
        return addAcceptedCertificate(new CMPCertificate(certHolder.toASN1Structure()), certHolder.getSignatureAlgorithm(), certReqID);
    }

    public CertificateConfirmationContentBuilder addAcceptedCertificate(CMPCertificate cmpCertificate, AlgorithmIdentifier sigAlg, ASN1Integer certReqID)
    {
        acceptedCerts.add(cmpCertificate);
        acceptedSignatureAlgorithms.add(sigAlg);
        acceptedReqIds.add(certReqID);

        return this;
    }

    public CertificateConfirmationContent build(DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        ASN1EncodableVector v = new ASN1EncodableVector(acceptedCerts.size());

        for (int i = 0; i != acceptedCerts.size(); i++)
        {
            byte[] certHash = CMPUtil.calculateCertHash((CMPCertificate)acceptedCerts.get(i),
                (AlgorithmIdentifier)acceptedSignatureAlgorithms.get(i), digesterProvider, digestAlgFinder);
            ASN1Integer reqID = (ASN1Integer)acceptedReqIds.get(i);

            v.add(new CertStatus(certHash, reqID));
        }

        CertConfirmContent content = CertConfirmContent.getInstance(new DERSequence(v));

        return new CertificateConfirmationContent(content, digestAlgFinder);
    }
}
