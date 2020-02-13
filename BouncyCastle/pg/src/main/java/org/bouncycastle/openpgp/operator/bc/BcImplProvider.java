package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bccrypto.AsymmetricBlockCipher;
import org.bouncycastle.bccrypto.BlockCipher;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.Signer;
import org.bouncycastle.bccrypto.Wrapper;
import org.bouncycastle.bccrypto.digests.MD2Digest;
import org.bouncycastle.bccrypto.digests.MD5Digest;
import org.bouncycastle.bccrypto.digests.RIPEMD160Digest;
import org.bouncycastle.bccrypto.digests.SHA1Digest;
import org.bouncycastle.bccrypto.digests.SHA224Digest;
import org.bouncycastle.bccrypto.digests.SHA256Digest;
import org.bouncycastle.bccrypto.digests.SHA384Digest;
import org.bouncycastle.bccrypto.digests.SHA512Digest;
import org.bouncycastle.bccrypto.digests.TigerDigest;
import org.bouncycastle.bccrypto.encodings.PKCS1Encoding;
import org.bouncycastle.bccrypto.engines.AESEngine;
import org.bouncycastle.bccrypto.engines.BlowfishEngine;
import org.bouncycastle.bccrypto.engines.CAST5Engine;
import org.bouncycastle.bccrypto.engines.CamelliaEngine;
import org.bouncycastle.bccrypto.engines.DESEngine;
import org.bouncycastle.bccrypto.engines.DESedeEngine;
import org.bouncycastle.bccrypto.engines.ElGamalEngine;
import org.bouncycastle.bccrypto.engines.IDEAEngine;
import org.bouncycastle.bccrypto.engines.RFC3394WrapEngine;
import org.bouncycastle.bccrypto.engines.RSABlindedEngine;
import org.bouncycastle.bccrypto.engines.TwofishEngine;
import org.bouncycastle.bccrypto.signers.DSADigestSigner;
import org.bouncycastle.bccrypto.signers.DSASigner;
import org.bouncycastle.bccrypto.signers.ECDSASigner;
import org.bouncycastle.bccrypto.signers.RSADigestSigner;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

class BcImplProvider
{
    static Digest createDigest(int algorithm)
        throws PGPException
    {
        switch (algorithm)
        {
        case HashAlgorithmTags.SHA1:
            return new SHA1Digest();
        case HashAlgorithmTags.SHA224:
            return new SHA224Digest();
        case HashAlgorithmTags.SHA256:
            return new SHA256Digest();
        case HashAlgorithmTags.SHA384:
            return new SHA384Digest();
        case HashAlgorithmTags.SHA512:
            return new SHA512Digest();
        case HashAlgorithmTags.MD2:
            return new MD2Digest();
        case HashAlgorithmTags.MD5:
            return new MD5Digest();
        case HashAlgorithmTags.RIPEMD160:
            return new RIPEMD160Digest();
        case HashAlgorithmTags.TIGER_192:
            return new TigerDigest();
        default:
            throw new PGPException("cannot recognise digest");
        }
    }

    static Signer createSigner(int keyAlgorithm, int hashAlgorithm)
        throws PGPException
    {
        switch(keyAlgorithm)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
            return new RSADigestSigner(createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.DSA:
            return new DSADigestSigner(new DSASigner(), createDigest(hashAlgorithm));
        case PublicKeyAlgorithmTags.ECDSA:
            return new DSADigestSigner(new ECDSASigner(), createDigest(hashAlgorithm));
        default:
            throw new PGPException("cannot recognise keyAlgorithm: " + keyAlgorithm);
        }
    }

    static BlockCipher createBlockCipher(int encAlgorithm)
        throws PGPException
    {
        BlockCipher engine;

        switch (encAlgorithm)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            engine = new AESEngine();
            break;
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            engine = new CamelliaEngine();
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            engine = new BlowfishEngine();
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            engine = new CAST5Engine();
            break;
        case SymmetricKeyAlgorithmTags.DES:
            engine = new DESEngine();
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            engine = new IDEAEngine();
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            engine = new TwofishEngine();
            break;
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            engine = new DESedeEngine();
            break;
        default:
            throw new PGPException("cannot recognise cipher");
        }

        return engine;
    }

    static Wrapper createWrapper(int encAlgorithm)
        throws PGPException
    {
        switch (encAlgorithm)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.AES_256:
            return new RFC3394WrapEngine(new AESEngine());
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return new RFC3394WrapEngine(new CamelliaEngine());
        default:
            throw new PGPException("unknown wrap algorithm: " + encAlgorithm);
        }
    }

    static AsymmetricBlockCipher createPublicKeyCipher(int encAlgorithm)
        throws PGPException
    {
        AsymmetricBlockCipher c;

        switch (encAlgorithm)
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_GENERAL:
            c = new PKCS1Encoding(new RSABlindedEngine());
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            c = new PKCS1Encoding(new ElGamalEngine());
            break;
        case PGPPublicKey.DSA:
            throw new PGPException("Can't use DSA for encryption.");
        case PGPPublicKey.ECDSA:
            throw new PGPException("Can't use ECDSA for encryption.");
        case PGPPublicKey.ECDH:
            throw new PGPException("Not implemented.");
        default:
            throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
        }

        return c;
    }
}
