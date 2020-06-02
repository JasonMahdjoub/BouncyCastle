package org.bouncycastle.bccrypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.bccrypto.CryptoServicesRegistrar;
import org.bouncycastle.bccrypto.KeyGenerationParameters;
import org.bouncycastle.bccrypto.params.ECDomainParameters;
import org.bouncycastle.bccrypto.params.ECKeyGenerationParameters;
import org.bouncycastle.bccrypto.params.ECPrivateKeyParameters;
import org.bouncycastle.bccrypto.params.ECPublicKeyParameters;
import org.bouncycastle.bcmath.ec.ECConstants;
import org.bouncycastle.bcmath.ec.ECMultiplier;
import org.bouncycastle.bcmath.ec.ECPoint;
import org.bouncycastle.bcmath.ec.FixedPointCombMultiplier;
import org.bouncycastle.bcmath.ec.WNafUtil;
import org.bouncycastle.bcutil.BigIntegers;

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

        if (this.random == null)
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }
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
