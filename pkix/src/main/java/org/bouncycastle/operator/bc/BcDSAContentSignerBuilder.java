package org.bouncycastle.operator.bc;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.crypto.signers.DSASigner;
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
