package org.bouncycastle.cert.path;

import org.bouncycastle.cert.X509CertificateHolder;
import com.distrimind.bouncycastle.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
