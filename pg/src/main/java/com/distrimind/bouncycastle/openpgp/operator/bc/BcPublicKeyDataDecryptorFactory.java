package com.distrimind.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.math.BigInteger;

import com.distrimind.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import com.distrimind.bouncycastle.bcpg.AEADEncDataPacket;
import com.distrimind.bouncycastle.bcpg.ECDHPublicBCPGKey;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPrivateKey;
import com.distrimind.bouncycastle.openpgp.PGPSessionKey;
import com.distrimind.bouncycastle.openpgp.operator.PGPDataDecryptor;
import com.distrimind.bouncycastle.openpgp.operator.PGPPad;
import com.distrimind.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import com.distrimind.bouncycastle.openpgp.operator.RFC6637Utils;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import com.distrimind.bouncycastle.crypto.agreement.X25519Agreement;
import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.distrimind.bouncycastle.crypto.params.ECDomainParameters;
import com.distrimind.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.X25519PublicKeyParameters;
import com.distrimind.bouncycastle.util.BigIntegers;

/**
 * A decryptor factory for handling public key decryption operations.
 */
public class BcPublicKeyDataDecryptorFactory
    implements PublicKeyDataDecryptorFactory
{
    private static final BcPGPKeyConverter KEY_CONVERTER = new BcPGPKeyConverter();

    private final PGPPrivateKey pgpPrivKey;

    public BcPublicKeyDataDecryptorFactory(PGPPrivateKey pgpPrivKey)
    {
        this.pgpPrivKey = pgpPrivKey;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
        throws PGPException
    {
        try
        {
            AsymmetricKeyParameter privKey = KEY_CONVERTER.getPrivateKey(pgpPrivKey);

            if (keyAlgorithm != PublicKeyAlgorithmTags.ECDH)
            {
                AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(keyAlgorithm);

                BufferedAsymmetricBlockCipher c1 = new BufferedAsymmetricBlockCipher(c);

                c1.init(false, privKey);

                if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
                    || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
                {
                    byte[] bi = secKeyData[0];

                    c1.processBytes(bi, 2, bi.length - 2);
                }
                else
                {
                    ElGamalPrivateKeyParameters parms = (ElGamalPrivateKeyParameters)privKey;
                    int size = (parms.getParameters().getP().bitLength() + 7) / 8;
                    byte[] tmp = new byte[size];

                    byte[] bi = secKeyData[0]; // encoded MPI
                    if (bi.length - 2 > size)  // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }

                    bi = secKeyData[1];  // encoded MPI
                    for (int i = 0; i != tmp.length; i++)
                    {
                        tmp[i] = 0;
                    }

                    if (bi.length - 2 > size) // leading Zero? Shouldn't happen but...
                    {
                        c1.processBytes(bi, 3, bi.length - 3);
                    }
                    else
                    {
                        System.arraycopy(bi, 2, tmp, tmp.length - (bi.length - 2), bi.length - 2);
                        c1.processBytes(tmp, 0, tmp.length);
                    }
                }

                return c1.doFinal();
            }
            else
            {
                ECDHPublicBCPGKey ecPubKey = (ECDHPublicBCPGKey)pgpPrivKey.getPublicKeyPacket().getKey();
                byte[] enc = secKeyData[0];

                int pLen = ((((enc[0] & 0xff) << 8) + (enc[1] & 0xff)) + 7) / 8;
                if ((2 + pLen + 1) > enc.length)
                {
                    throw new PGPException("encoded length out of range");
                }

                byte[] pEnc = new byte[pLen];
                System.arraycopy(enc, 2, pEnc, 0, pLen);

                int keyLen = enc[pLen + 2] & 0xff;
                if ((2 + pLen + 1 + keyLen) > enc.length)
                {
                    throw new PGPException("encoded length out of range");
                }

                byte[] keyEnc = new byte[keyLen];
                System.arraycopy(enc, 2 + pLen + 1, keyEnc, 0, keyLen);

                byte[] secret;
                // XDH
                if (ecPubKey.getCurveOID().equals(CryptlibObjectIdentifiers.curvey25519))
                {
                    // skip the 0x40 header byte.
                    if (pEnc.length != (1 + X25519PublicKeyParameters.KEY_SIZE) || 0x40 != pEnc[0])
                    {
                        throw new IllegalArgumentException("Invalid Curve25519 public key");
                    }

                    X25519PublicKeyParameters ephPub = new X25519PublicKeyParameters(pEnc, 1);

                    X25519Agreement agreement = new X25519Agreement();
                    agreement.init(privKey);

                    secret = new byte[agreement.getAgreementSize()];
                    agreement.calculateAgreement(ephPub, secret, 0);
                }
                else
                {
                    ECDomainParameters ecParameters = ((ECPrivateKeyParameters)privKey).getParameters();

                    ECPublicKeyParameters ephPub = new ECPublicKeyParameters(ecParameters.getCurve().decodePoint(pEnc),
                        ecParameters);

                    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
                    agreement.init(privKey);
                    BigInteger S = agreement.calculateAgreement(ephPub);
                    secret = BigIntegers.asUnsignedByteArray(agreement.getFieldSize(), S);
                }

                RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator(
                    new BcPGPDigestCalculatorProvider().get(ecPubKey.getHashAlgorithm()),
                    ecPubKey.getSymmetricKeyAlgorithm());
                byte[] userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(pgpPrivKey.getPublicKeyPacket(),
                    new BcKeyFingerprintCalculator());

                KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial));

                Wrapper c = BcImplProvider.createWrapper(ecPubKey.getSymmetricKeyAlgorithm());
                c.init(false, key);
                return PGPPad.unpadSessionData(c.unwrap(keyEnc, 0, keyEnc.length));
            }
        }
        catch (IOException e)
        {
            throw new PGPException("exception creating user keying material: " + e.getMessage(), e);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception decrypting session info: " + e.getMessage(), e);
        }

    }

    // OpenPGP v4
    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    // OpenPGP v5
    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException
    {
        return BcAEADUtil.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }
}
