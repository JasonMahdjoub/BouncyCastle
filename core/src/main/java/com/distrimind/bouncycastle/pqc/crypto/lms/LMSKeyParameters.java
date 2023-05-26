package com.distrimind.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.util.Encodable;

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
