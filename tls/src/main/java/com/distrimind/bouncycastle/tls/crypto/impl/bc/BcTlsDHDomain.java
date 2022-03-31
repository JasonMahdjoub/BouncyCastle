package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.agreement.DHBasicAgreement;
import com.distrimind.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.params.DHKeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.DHParameters;
import com.distrimind.bouncycastle.crypto.params.DHPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.DHPublicKeyParameters;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsDHUtils;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.DHGroup;
import com.distrimind.bouncycastle.tls.crypto.TlsAgreement;
import com.distrimind.bouncycastle.tls.crypto.TlsDHConfig;
import com.distrimind.bouncycastle.tls.crypto.TlsDHDomain;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * BC light-weight support class for Diffie-Hellman key pair generation and key agreement over a specified Diffie-Hellman configuration.
 */
public class BcTlsDHDomain implements TlsDHDomain
{
    private static byte[] encodeValue(DHParameters dh, boolean padded, BigInteger x)
    {
        return padded
            ?   BigIntegers.asUnsignedByteArray(getValueLength(dh), x)
            :   BigIntegers.asUnsignedByteArray(x);
    }

    private static int getValueLength(DHParameters dh)
    {
        return (dh.getP().bitLength() + 7) / 8;
    }

    public static BcTlsSecret calculateDHAgreement(BcTlsCrypto crypto, DHPrivateKeyParameters privateKey,
        DHPublicKeyParameters publicKey, boolean padded)
    {
        DHBasicAgreement basicAgreement = new DHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);
        byte[] secret = encodeValue(privateKey.getParameters(), padded, agreementValue);
        return crypto.adoptLocalSecret(secret);
    }

    public static DHParameters getParameters(TlsDHConfig dhConfig)
    {
        DHGroup dhGroup = TlsDHUtils.getDHGroup(dhConfig);
        if (dhGroup == null)
        {
            throw new IllegalArgumentException("No DH configuration provided");
        }

        return new DHParameters(dhGroup.getP(), dhGroup.getG(), dhGroup.getQ(), dhGroup.getL());
    }

    protected BcTlsCrypto crypto;
    protected TlsDHConfig dhConfig;
    protected DHParameters dhParameters;

    public BcTlsDHDomain(BcTlsCrypto crypto, TlsDHConfig dhConfig)
    {
        this.crypto = crypto;
        this.dhConfig = dhConfig;
        this.dhParameters = getParameters(dhConfig);
    }

    public BcTlsSecret calculateDHAgreement(DHPrivateKeyParameters privateKey, DHPublicKeyParameters publicKey)
    {
        return calculateDHAgreement(crypto, privateKey, publicKey, dhConfig.isPadded());
    }

    public TlsAgreement createDH()
    {
        return new BcTlsDH(this);
    }

    public BigInteger decodeParameter(byte[] encoding) throws IOException
    {
        if (dhConfig.isPadded() && getValueLength(dhParameters) != encoding.length)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return new BigInteger(1, encoding);
    }

    public DHPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException
    {
        /*
         * RFC 7919 3. [..] the client MUST verify that dh_Ys is in the range 1 < dh_Ys < dh_p - 1.
         * If dh_Ys is not in this range, the client MUST terminate the connection with a fatal
         * handshake_failure(40) alert.
         */
        try
        {
            BigInteger y = decodeParameter(encoding);

            return new DHPublicKeyParameters(y, dhParameters);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure, e);
        }
    }

    public byte[] encodeParameter(BigInteger x) throws IOException
    {
        return encodeValue(dhParameters, dhConfig.isPadded(), x);
    }

    public byte[] encodePublicKey(DHPublicKeyParameters publicKey) throws IOException
    {
        return encodeValue(dhParameters, true, publicKey.getY());
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
        keyPairGenerator.init(new DHKeyGenerationParameters(crypto.getSecureRandom(), dhParameters));
        return keyPairGenerator.generateKeyPair();
    }
}