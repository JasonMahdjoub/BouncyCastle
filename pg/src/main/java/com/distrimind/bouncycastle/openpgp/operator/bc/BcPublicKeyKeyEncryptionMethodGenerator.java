package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import com.distrimind.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import com.distrimind.bouncycastle.bcpg.PublicKeyPacket;
import com.distrimind.bouncycastle.bcpg.ECDHPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.MPInteger;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import com.distrimind.bouncycastle.crypto.agreement.X25519Agreement;
import com.distrimind.bouncycastle.crypto.generators.ECKeyPairGenerator;
import com.distrimind.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECKeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import com.distrimind.bouncycastle.crypto.params.X25519PublicKeyParameters;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPPad;
import com.distrimind.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import com.distrimind.bouncycastle.openpgp.operator.RFC6637Utils;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * A method generator for supporting public key based encryption operations.
 */
public class BcPublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private static final byte X_HDR = 0x40;

    private SecureRandom random;
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    /**
     * Create a public key encryption method generator with the method to be based on the passed in key.
     *
     * @param key   the public key to use for encryption.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current generator.
     */
    public BcPublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter cryptoPublicKey = keyConverter.getPublicKey(pubKey);

            if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags.ECDH)
            {
                PublicKeyPacket pubKeyPacket = pubKey.getPublicKeyPacket();
                ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pubKeyPacket.getKey();

                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pubKeyPacket,
                    new BcKeyFingerprintCalculator());

                if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
                    gen.init(new X25519KeyGenerationParameters(random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.init(ephKp.getPrivate());

                    byte[] secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(cryptoPublicKey, secret, 0);

                    byte[] ephPubEncoding = new byte[1 + X25519PublicKeyParameters.KEY_SIZE];
                    ephPubEncoding[0] = X_HDR;
                    ((X25519PublicKeyParameters)ephKp.getPublic()).encode(ephPubEncoding, 1);

                    return encryptSessionInfo(ecPubKey, sessionInfo, secret, userKeyingMaterial, ephPubEncoding);
                }
                else
                {
                    ECDomainParameters ecParams = ((ECPublicKeyParameters)cryptoPublicKey).getParameters();

                    ECKeyPairGenerator gen = new ECKeyPairGenerator();
                    gen.init(new ECKeyGenerationParameters(ecParams, random));

                    AsymmetricCipherKeyPair ephKp = gen.generateKeyPair();

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(ephKp.getPrivate());
                    BigInteger S = agreement.calculateAgreement(cryptoPublicKey);
                    byte[] secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);

                    byte[] ephPubEncoding = ((ECPublicKeyParameters)ephKp.getPublic()).getQ().getEncoded(false);

                    return encryptSessionInfo(ecPubKey, sessionInfo, secret, userKeyingMaterial, ephPubEncoding);
                }
            }
            else
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(pubKey.getAlgorithm());

                c.init(true, new ParametersWithRandom(cryptoPublicKey, random));

                return c.processBlock(sessionInfo, 0, sessionInfo.length);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
    }

    private byte[] encryptSessionInfo(ECDHPublicBCPGKey ecPubKey, byte[] sessionInfo, byte[] secret,
        byte[] userKeyingMaterial, byte[] ephPubEncoding) throws IOException, PGPException
    {
        RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
            new BcPGPDigestCalculatorProvider().get(ecPubKey.getHashAlgorithm()), ecPubKey.getSymmetricKeyAlgorithm());
        KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

        byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo, sessionKeyObfuscation);

        Wrapper c = BcImplProvider.createWrapper(ecPubKey.getSymmetricKeyAlgorithm());
        c.init(true, new ParametersWithRandom(key, random));
        byte[] C = c.wrap(paddedSessionData, 0, paddedSessionData.length);

        byte[] VB = new MPInteger(new BigInteger(1, ephPubEncoding)).getEncoded();

        byte[] rv = new byte[VB.length + 1 + C.length];
        System.arraycopy(VB, 0, rv, 0, VB.length);
        rv[VB.length] = (byte)C.length;
        System.arraycopy(C, 0, rv, VB.length + 1, C.length);
        return rv;
    }
}
