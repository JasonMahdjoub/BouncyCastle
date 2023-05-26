package com.distrimind.bouncycastle.pqc.jcajce.provider.util;

import java.security.InvalidKeyException;

import com.distrimind.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.distrimind.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.distrimind.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.distrimind.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import com.distrimind.bouncycastle.crypto.DerivationFunction;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.Xof;
import com.distrimind.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA512Digest;
import com.distrimind.bouncycastle.crypto.digests.SHAKEDigest;
import com.distrimind.bouncycastle.crypto.engines.AESEngine;
import com.distrimind.bouncycastle.crypto.engines.ARIAEngine;
import com.distrimind.bouncycastle.crypto.engines.CamelliaEngine;
import com.distrimind.bouncycastle.crypto.engines.RFC3394WrapEngine;
import com.distrimind.bouncycastle.crypto.engines.RFC5649WrapEngine;
import com.distrimind.bouncycastle.crypto.engines.SEEDEngine;
import com.distrimind.bouncycastle.crypto.generators.KDF2BytesGenerator;
import com.distrimind.bouncycastle.crypto.params.KDFParameters;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.jcajce.spec.KTSParameterSpec;
import com.distrimind.bouncycastle.util.Arrays;

public class WrapUtil
{
    public static Wrapper getKeyWrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(true, new KeyParameter(secret));
        }
        else
        {
            kWrap.init(true, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getKeyUnwrapper(KTSParameterSpec ktsParameterSpec, byte[] secret)
        throws InvalidKeyException
    {
        Wrapper kWrap = getWrapper(ktsParameterSpec.getKeyAlgorithmName());

        AlgorithmIdentifier kdfAlgorithm = ktsParameterSpec.getKdfAlgorithm();
        if (kdfAlgorithm == null)
        {
            kWrap.init(false, new KeyParameter(secret));
        }
        else
        {
            kWrap.init(false, new KeyParameter(makeKeyBytes(ktsParameterSpec, secret)));
        }

        return kWrap;
    }

    public static Wrapper getWrapper(String keyAlgorithmName)
    {
        Wrapper kWrap;

        if (keyAlgorithmName.equalsIgnoreCase("AESWRAP") || keyAlgorithmName.equalsIgnoreCase("AES"))
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

    private static byte[] makeKeyBytes(KTSParameterSpec ktsSpec, byte[] secret)
        throws InvalidKeyException
    {
        AlgorithmIdentifier kdfAlgorithm = ktsSpec.getKdfAlgorithm();
        byte[] otherInfo = ktsSpec.getOtherInfo();
        byte[] keyBytes = new byte[(ktsSpec.getKeySize() + 7) / 8];

        if (X9ObjectIdentifiers.id_kdf_kdf2.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new KDF2BytesGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (X9ObjectIdentifiers.id_kdf_kdf3.equals(kdfAlgorithm.getAlgorithm()))
        {
            AlgorithmIdentifier digAlg = AlgorithmIdentifier.getInstance(kdfAlgorithm.getParameters());
            DerivationFunction kdf = new ConcatenationKDFGenerator(getDigest(digAlg.getAlgorithm()));

            kdf.init(new KDFParameters(secret, otherInfo));

            kdf.generateBytes(keyBytes, 0, keyBytes.length);
        }
        else if (NISTObjectIdentifiers.id_shake256.equals(kdfAlgorithm.getAlgorithm()))
        {
             Xof xof = new SHAKEDigest(256);

             xof.update(secret, 0, secret.length);
             xof.update(otherInfo, 0, otherInfo.length);

             xof.doFinal(keyBytes, 0, keyBytes.length);
        }
        else
        {
            throw new InvalidKeyException("Unrecognized KDF: " + kdfAlgorithm.getAlgorithm());
        }

        Arrays.fill(secret, (byte)0);

        return keyBytes;
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }
}
