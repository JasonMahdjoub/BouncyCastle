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
import com.distrimind.bouncycastle.crypto.params.GOST3410KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.GOST3410Parameters;
import com.distrimind.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import com.distrimind.bouncycastle.math.ec.WNafUtil;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * a GOST3410 key pair generator.
 * This generates GOST3410 keys in line with the method described
 * in GOST R 34.10-94.
 */
public class GOST3410KeyPairGenerator
        implements AsymmetricCipherKeyPairGenerator
    {
        private GOST3410KeyGenerationParameters param;

        public void init(
            KeyGenerationParameters param)
        {
            this.param = (GOST3410KeyGenerationParameters)param;

            CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("GOST3410KeyGen", ConstraintUtils.bitsOfSecurityFor(this.param.getParameters().getP()), this.param.getParameters(), CryptoServicePurpose.KEYGEN));
        }

        public AsymmetricCipherKeyPair generateKeyPair()
        {
            BigInteger      p, q, a, x, y;
            GOST3410Parameters   GOST3410Params = param.getParameters();
            SecureRandom    random = param.getRandom();

            q = GOST3410Params.getQ();
            p = GOST3410Params.getP();
            a = GOST3410Params.getA();

            int minWeight = 64;
            for (;;)
            {
                x = BigIntegers.createRandomBigInteger(256, random);

                if (x.signum() < 1 || x.compareTo(q) >= 0)
                {
                    continue;
                }

                if (WNafUtil.getNafWeight(x) < minWeight)
                {
                    continue;
                }

                break;
            }

            //
            // calculate the public key.
            //
            y = a.modPow(x, p);

            return new AsymmetricCipherKeyPair(
                    new GOST3410PublicKeyParameters(y, GOST3410Params),
                    new GOST3410PrivateKeyParameters(x, GOST3410Params));
        }
    }
