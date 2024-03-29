package com.distrimind.bouncycastle.operator.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.signers.Ed25519Signer;
import com.distrimind.bouncycastle.crypto.signers.Ed448Signer;
import com.distrimind.bouncycastle.crypto.util.PublicKeyFactory;
import com.distrimind.bouncycastle.operator.OperatorCreationException;

public class BcEdDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    public static final byte[] DEFAULT_CONTEXT = new byte[0];

    public BcEdDSAContentVerifierProviderBuilder()
    {
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed448))
        {
            return new Ed448Signer(DEFAULT_CONTEXT);
        }
        else
        {
            return new Ed25519Signer();
        }
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}