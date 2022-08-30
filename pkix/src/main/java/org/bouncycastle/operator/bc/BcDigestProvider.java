package org.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.operator.OperatorCreationException;

public interface BcDigestProvider
{
    ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException;
}
