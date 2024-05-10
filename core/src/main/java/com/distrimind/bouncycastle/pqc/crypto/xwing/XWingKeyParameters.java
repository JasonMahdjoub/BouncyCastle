package com.distrimind.bouncycastle.pqc.crypto.xwing;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XWingKeyParameters
    extends AsymmetricKeyParameter
{
    XWingKeyParameters(
        boolean isPrivate)
    {
        super(isPrivate);
    }
}
