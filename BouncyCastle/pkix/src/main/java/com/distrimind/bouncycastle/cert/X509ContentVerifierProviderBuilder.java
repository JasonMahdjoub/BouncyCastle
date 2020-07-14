package com.distrimind.bouncycastle.cert;

import com.distrimind.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.distrimind.bouncycastle.operator.ContentVerifierProvider;
import com.distrimind.bouncycastle.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder
{
    ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
        throws OperatorCreationException;

    ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
        throws OperatorCreationException;
}
