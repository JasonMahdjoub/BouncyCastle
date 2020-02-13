package org.bouncycastle.operator.bc;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.Signer;
import org.bouncycastle.bccrypto.signers.DSADigestSigner;
import org.bouncycastle.bccrypto.signers.DSASigner;
import org.bouncycastle.operator.OperatorCreationException;

public class BcDSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcDSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new DSASigner(), dig);
    }
}
