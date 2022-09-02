package com.distrimind.bouncycastle.its.bc;

import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.its.ITSCertificate;
import com.distrimind.bouncycastle.its.ITSExplicitCertificateBuilder;
import com.distrimind.bouncycastle.its.ITSPublicEncryptionKey;
import com.distrimind.bouncycastle.its.operator.ITSContentSigner;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import com.distrimind.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey,
        ECPublicKeyParameters encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
        }

        return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey), publicEncryptionKey);
    }
}
