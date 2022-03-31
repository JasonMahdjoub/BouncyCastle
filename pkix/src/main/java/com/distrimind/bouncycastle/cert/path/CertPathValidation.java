package com.distrimind.bouncycastle.cert.path;

import com.distrimind.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
