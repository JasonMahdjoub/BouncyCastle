package org.bouncycastle.operator.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.crypto.signers.ECDSASigner;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;

public class BcECContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcECContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
    {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlg);

        return new DSADigestSigner(new ECDSASigner(), dig);
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}
