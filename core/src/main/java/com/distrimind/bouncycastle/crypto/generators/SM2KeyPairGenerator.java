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

public class SM2KeyPairGenerator
    extends ECKeyPairGenerator
{
    public SM2KeyPairGenerator()
    {
        super("SM2KeyGen");
    }

    protected boolean isOutOfRangeD(BigInteger d, BigInteger n)
    {
        return d.compareTo(ONE) < 0 || (d.compareTo(n.subtract(BigIntegers.ONE)) >= 0);
    }
}
