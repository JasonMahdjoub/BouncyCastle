package com.distrimind.bouncycastle.tsp.ers;

import com.distrimind.bouncycastle.asn1.tsp.EvidenceRecord;
import com.distrimind.bouncycastle.operator.DigestCalculatorProvider;
import com.distrimind.bouncycastle.tsp.TSPException;

public class ERSEvidenceRecordGenerator
{
    private final DigestCalculatorProvider digCalcProv;

    public ERSEvidenceRecordGenerator(DigestCalculatorProvider digCalcProv)
    {
        this.digCalcProv = digCalcProv;
    }

    public ERSEvidenceRecord generate(ERSArchiveTimeStamp archiveTimeStamp)
        throws TSPException, ERSException
    {
        return new ERSEvidenceRecord(
            new EvidenceRecord(null, null, archiveTimeStamp.toASN1Structure()), digCalcProv);
    }
}
