package org.bouncycastle.operator.bc;

import org.bouncycastle.bcasn1.x509.AlgorithmIdentifier;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.Signer;
import org.bouncycastle.bccrypto.signers.RSADigestSigner;
import org.bouncycastle.operator.OperatorCreationException;

public class BcRSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcRSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new RSADigestSigner(dig);
    }
}
