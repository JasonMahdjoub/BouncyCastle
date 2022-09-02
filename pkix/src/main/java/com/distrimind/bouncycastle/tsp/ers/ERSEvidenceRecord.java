package com.distrimind.bouncycastle.tsp.ers;

import java.io.IOException;
import java.util.Date;

import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.cms.SignerInformationVerifier;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;
import com.distrimind.bouncycastle.tsp.TSPException;
import com.distrimind.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import com.distrimind.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import com.distrimind.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import com.distrimind.bouncycastle.asn1.tsp.EvidenceRecord;

/**
 * RFC 4998 Evidence Record.
 */
public class ERSEvidenceRecord
{
    private final EvidenceRecord evidenceRecord;
    private final DigestCalculatorProvider digestCalculatorProvider;
    private final ERSArchiveTimeStamp lastArchiveTimeStamp;

    public ERSEvidenceRecord(byte[] evidenceRecord, DigestCalculatorProvider digestCalculatorProvider)
        throws TSPException, ERSException
    {
        this(EvidenceRecord.getInstance(evidenceRecord), digestCalculatorProvider);
    }
    
    public ERSEvidenceRecord(EvidenceRecord evidenceRecord, DigestCalculatorProvider digestCalculatorProvider)
        throws TSPException, ERSException
    {
        this.evidenceRecord = evidenceRecord;
        this.digestCalculatorProvider = digestCalculatorProvider;

        ArchiveTimeStampSequence sequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChain[] chains = sequence.getArchiveTimeStampChains();
        ArchiveTimeStampChain chain = chains[chains.length - 1];
        ArchiveTimeStamp[] archiveTimestamps = chain.getArchiveTimestamps();

       this.lastArchiveTimeStamp = new ERSArchiveTimeStamp(archiveTimestamps[archiveTimestamps.length - 1], digestCalculatorProvider);
    }

    public ERSArchiveTimeStamp getLastArchiveTimeStamp()
    {
        return lastArchiveTimeStamp;
    }

    public void validatePresent(ERSData data, Date atDate)
        throws ERSException, OperatorCreationException
    {
        lastArchiveTimeStamp.validatePresent(data, atDate);
    }

    public void validatePresent(byte[] hash, Date atDate)
        throws ERSException, OperatorCreationException
    {
        lastArchiveTimeStamp.validatePresent(hash, atDate);
    }

    /**
     * Return the TimeStamp signing certificate if it is present.
     *
     * @return the TimeStamp signing certificate.
     */
    public X509CertificateHolder getSigningCertificate()
    {
        return lastArchiveTimeStamp.getSigningCertificate();
    }

    /**
     * Validate the time stamp associated with this ArchiveTimeStamp.
     *
     * @param verifier signer verifier for the contained time stamp.
     * @throws TSPException in case of validation failure or error.
     */
    public void validate(SignerInformationVerifier verifier)
        throws TSPException
    {
        lastArchiveTimeStamp.validate(verifier);
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return evidenceRecord.getEncoded();
    }
}
