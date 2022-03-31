package com.distrimind.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECKeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.math.ec.ECConstants;
import com.distrimind.bouncycastle.math.ec.ECMultiplier;
import com.distrimind.bouncycastle.math.ec.ECPoint;
import com.distrimind.bouncycastle.math.ec.FixedPointCombMultiplier;
import com.distrimind.bouncycastle.math.ec.WNafUtil;
import com.distrimind.bouncycastle.util.BigIntegers;

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    SecureRandom        random;

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = BigIntegers.createRandomBigInteger(nBitLength, random);

            if (d.compareTo(ONE) < 0  || (d.compareTo(n) >= 0))
            {
                continue;
            }

            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
