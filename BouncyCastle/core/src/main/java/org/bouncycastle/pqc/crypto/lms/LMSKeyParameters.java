package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;
import org.bouncycastle.bcutil.Encodable;

public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable
{
    protected LMSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded()
        throws IOException;
}
