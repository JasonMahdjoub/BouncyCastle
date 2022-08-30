package com.distrimind.bouncycastle.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import com.distrimind.bouncycastle.crypto.KeyParser;
import com.distrimind.bouncycastle.crypto.params.DHParameters;
import com.distrimind.bouncycastle.util.io.Streams;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.DHPublicKeyParameters;

public class DHIESPublicKeyParser
    implements KeyParser
{
    private DHParameters dhParams;

    public DHIESPublicKeyParser(DHParameters dhParams)
    {
        this.dhParams = dhParams;
    }

    public AsymmetricKeyParameter readKey(InputStream stream)
        throws IOException
    {
        byte[] V = new byte[(dhParams.getP().bitLength() + 7) / 8];

        Streams.readFully(stream, V, 0, V.length);

        return new DHPublicKeyParameters(new BigInteger(1, V), dhParams);
    }
}
