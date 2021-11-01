package com.distrimind.bouncycastle.openpgp.operator.bc;

import com.distrimind.bouncycastle.bcpg.HashAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import com.distrimind.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import com.distrimind.bouncycastle.crypto.AsymmetricBlockCipher;
import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.bouncycastle.crypto.DataLengthException;
import com.distrimind.bouncycastle.crypto.Digest;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.Wrapper;
import com.distrimind.bouncycastle.crypto.digests.MD2Digest;
import com.distrimind.bouncycastle.crypto.digests.MD5Digest;
import com.distrimind.bouncycastle.crypto.digests.RIPEMD160Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA224Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA256Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA384Digest;
import com.distrimind.bouncycastle.crypto.digests.SHA512Digest;
import com.distrimind.bouncycastle.crypto.digests.TigerDigest;
import com.distrimind.bouncycastle.crypto.encodings.PKCS1Encoding;
import com.distrimind.bouncycastle.crypto.engines.AESEngine;
import com.distrimind.bouncycastle.crypto.engines.BlowfishEngine;
import com.distrimind.bouncycastle.crypto.engines.CAST5Engine;
import com.distrimind.bouncycastle.crypto.engines.CamelliaEngine;
import com.distrimind.bouncycastle.crypto.engines.DESEngine;
import com.distrimind.bouncycastle.crypto.engines.DESedeEngine;
import com.distrimind.bouncycastle.crypto.engines.ElGamalEngine;
import com.distrimind.bouncycastle.crypto.engines.IDEAEngine;
import com.distrimind.bouncycastle.crypto.engines.RFC3394WrapEngine;
import com.distrimind.bouncycastle.crypto.engines.RSABlindedEngine;
import com.distrimind.bouncycastle.crypto.engines.TwofishEngine;
import com.distrimind.bouncycastle.crypto.signers.DSADigestSigner;
import com.distrimind.bouncycastle.crypto.signers.DSASigner;
import com.distrimind.bouncycastle.crypto.signers.ECDSASigner;
import com.distrimind.bouncycastle.crypto.signers.Ed25519Signer;
import com.distrimind.bouncycastle.crypto.signers.RSADigestSigner;
import com.distrimind.bouncycastle.openpgp.PGPException;
import com.distrimind.bouncycastle.openpgp.PGPPublicKey;
import com.distrimind.bouncycastle.util.Arrays;

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
        case PublicKeyAlgorithmTags.EDDSA:
            return new EdDsaSigner(new Ed25519Signer(), createDigest(hashAlgorithm));
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

    private static class EdDsaSigner
        implements Signer
    {
        private final Signer signer;
        private final Digest digest;
        private final byte[] digBuf;

        EdDsaSigner(Signer signer, Digest digest)
        {
            this.signer = signer;
            this.digest = digest;
            this.digBuf = new byte[digest.getDigestSize()];
        }

        public void init(boolean forSigning, CipherParameters param)
        {
            this.signer.init(forSigning, param);
            this.digest.reset();
        }

        public void update(byte b)
        {
            this.digest.update(b);
        }

        public void update(byte[] in, int off, int len)
        {
            this.digest.update(in, off, len);
        }

        public byte[] generateSignature()
            throws CryptoException, DataLengthException
        {
            digest.doFinal(digBuf, 0);

            signer.update(digBuf, 0, digBuf.length);

            return signer.generateSignature();
        }

        public boolean verifySignature(byte[] signature)
        {
            digest.doFinal(digBuf, 0);
            
            signer.update(digBuf, 0, digBuf.length);

            return signer.verifySignature(signature);
        }

        public void reset()
        {
            Arrays.clear(digBuf);
            signer.reset();
            digest.reset();
        }
    }
}
