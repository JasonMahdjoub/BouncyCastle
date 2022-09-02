package com.distrimind.bouncycastle.cms.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.operator.bc.BcRSAAsymmetricKeyWrapper;

public class BcRSAKeyTransRecipientInfoGenerator
    extends BcKeyTransRecipientInfoGenerator
{
    public BcRSAKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier encAlgId, AsymmetricKeyParameter publicKey)
    {
        super(subjectKeyIdentifier, new BcRSAAsymmetricKeyWrapper(encAlgId, publicKey));
    }

    public BcRSAKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert)
        throws IOException
    {
        super(recipientCert, new BcRSAAsymmetricKeyWrapper(recipientCert.getSubjectPublicKeyInfo().getAlgorithm(), recipientCert.getSubjectPublicKeyInfo()));
    }
}
