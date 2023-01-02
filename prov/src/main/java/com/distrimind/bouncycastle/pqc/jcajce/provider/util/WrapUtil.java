package com.distrimind.bouncycastle.pqc.jcajce.provider.util;

import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.engines.*;

public class WrapUtil
{
    public static Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AES"))
        {
            kWrap = new RFC3394WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA"))
        {
            kWrap = new RFC3394WrapEngine(new ARIAEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia"))
        {
            kWrap = new RFC3394WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("SEED"))
        {
            kWrap = new RFC3394WrapEngine(new SEEDEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("AES-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new AESEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("Camellia-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new CamelliaEngine());
        }
        else if (keyAlgorithmName.equalsIgnoreCase("ARIA-KWP"))
        {
            kWrap = new RFC5649WrapEngine(new ARIAEngine());
        }
        else
        {
            throw new UnsupportedOperationException("unknown key algorithm: " + keyAlgorithmName);
        }
        return kWrap;
    }
}
