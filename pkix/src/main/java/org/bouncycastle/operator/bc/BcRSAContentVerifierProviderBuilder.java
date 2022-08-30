package org.bouncycastle.operator.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.signers.RSADigestSigner;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;

public class BcRSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcRSAContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
    {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlg);

        return new RSADigestSigner(dig);
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}