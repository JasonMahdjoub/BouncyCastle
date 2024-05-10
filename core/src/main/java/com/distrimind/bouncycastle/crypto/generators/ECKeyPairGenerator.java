package com.distrimind.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.CryptoServicePurpose;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.constraints.ConstraintUtils;
import com.distrimind.bouncycastle.crypto.constraints.DefaultServiceProperties;
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
    private final String name;
    ECDomainParameters  params;
    SecureRandom        random;

    public ECKeyPairGenerator()
    {
        this("ECKeyGen");
    }

    protected ECKeyPairGenerator(String name)
    {
        this.name = name;
    }

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(name, ConstraintUtils.bitsOfSecurityFor(this.params.getCurve()), ecP.getDomainParameters(), CryptoServicePurpose.KEYGEN));
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

            if (isOutOfRangeD(d, n))
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

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n) >= 0);
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
