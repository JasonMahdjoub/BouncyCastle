package org.bouncycastle.oer.test;

import com.distrimind.bouncycastle.asn1.ASN1Encodable;

public interface Populate
{
    boolean isFinished(int tick);
    ASN1Encodable populate(int tick, ASN1Encodable[] priorValues);
}
