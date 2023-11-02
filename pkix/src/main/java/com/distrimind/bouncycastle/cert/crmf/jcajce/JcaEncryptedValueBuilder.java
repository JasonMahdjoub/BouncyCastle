package com.distrimind.bouncycastle.cert.crmf.jcajce;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.distrimind.bouncycastle.cert.crmf.CRMFException;
import com.distrimind.bouncycastle.cert.crmf.EncryptedValueBuilder;
import com.distrimind.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import com.distrimind.bouncycastle.operator.KeyWrapper;
import com.distrimind.bouncycastle.operator.OutputEncryptor;
import com.distrimind.bouncycastle.asn1.crmf.EncryptedValue;
import com.distrimind.bouncycastle.asn1.pkcs.PrivateKeyInfo;

/**
 * JCA convenience class for EncryptedValueBuilder
 */
public class JcaEncryptedValueBuilder
    extends EncryptedValueBuilder
{
    public JcaEncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor)
    {
        super(wrapper, encryptor);
    }

    /**
     * Build an EncryptedValue structure containing the passed in certificate.
     *
     * @param certificate the certificate to be encrypted.
     * @return an EncryptedValue containing the encrypted certificate.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(X509Certificate certificate)
        throws CertificateEncodingException, CRMFException
    {
        return build(new JcaX509CertificateHolder(certificate));
    }

    /**
     * Build an EncryptedValue structure containing the private key details contained in
     * the passed PrivateKey.
     *
     * @param privateKey the asymmetric private key.
     * @return an EncryptedValue containing an EncryptedPrivateKeyInfo structure.
     * @throws CRMFException on a failure to encrypt the data, or wrap the symmetric key for this value.
     */
    public EncryptedValue build(PrivateKey privateKey)
        throws CertificateEncodingException, CRMFException
    {
        return build(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
