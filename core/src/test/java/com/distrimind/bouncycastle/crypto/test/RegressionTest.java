package com.distrimind.bouncycastle.crypto.test;

import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests =
        {
            new AESTest(),
            new AESLightTest(),
            new AESFastTest(),
            new AESWrapTest(),
            new AESWrapPadTest(),
            new ARIATest(),
            new DESTest(),
            new DESedeTest(),
            new ModeTest(),
            new PaddingTest(),
            new DHTest(),
            new ElGamalTest(),
            new DSATest(),
            new ECTest(),
            new DeterministicDSATest(),
            new GOST3410Test(),
            new ECGOST3410Test(),
            new ECIESTest(),
            new ECNRTest(),
            new MacTest(),
            new GOST28147MacTest(),
            new RC2Test(),
            new RC2WrapTest(),
            new RC4Test(),
            new RC5Test(),
            new RC6Test(),
            new RijndaelTest(),
            new SerpentTest(),
            new TnepresTest(),
            new CamelliaTest(),
            new CamelliaLightTest(),
            new DigestRandomNumberTest(),
            new SkipjackTest(),
            new BlowfishTest(),
            new TwofishTest(),
            new Threefish256Test(),
            new Threefish512Test(),
            new Threefish1024Test(),
            new SkeinDigestTest(),
            new SkeinMacTest(),
            new CAST5Test(),
            new CAST6Test(),
            new GOST28147Test(),
            new IDEATest(),
            new RSATest(),
            new RSABlindedTest(),
            new RSADigestSignerTest(),
            new PSSBlindTest(),
            new ISO9796Test(),
            new ISO9797Alg3MacTest(),
            new MD2DigestTest(),
            new MD4DigestTest(),
            new MD5DigestTest(),
            new SHA1DigestTest(),
            new SHA224DigestTest(),
            new SHA256DigestTest(),
            new SHA384DigestTest(),
            new SHA512DigestTest(),
            new SHA512t224DigestTest(),
            new SHA512t256DigestTest(),
            new SHA3DigestTest(),
            new RIPEMD128DigestTest(),
            new RIPEMD160DigestTest(),
            new RIPEMD256DigestTest(),
            new RIPEMD320DigestTest(),
            new TigerDigestTest(),
            new GOST3411DigestTest(),
            new GOST3411_2012_256DigestTest(),
            new GOST3411_2012_512DigestTest(),
            new WhirlpoolDigestTest(),
            new MD5HMacTest(),
            new SHA1HMacTest(),
            new SHA224HMacTest(),
            new SHA256HMacTest(),
            new SHA384HMacTest(),
            new SHA512HMacTest(),
            new RIPEMD128HMacTest(),
            new RIPEMD160HMacTest(),
            new OAEPTest(),
            new PSSTest(),
            new CTSTest(),
            new NISTCTSTest(),
            new NISTECCTest(),
            new CCMTest(),
            new PKCS5Test(),
            new PKCS12Test(),
            new KDF1GeneratorTest(),
            new KDF2GeneratorTest(),
            new MGF1GeneratorTest(),
            new HKDFGeneratorTest(),
            new DHKEKGeneratorTest(),
            new ECDHKEKGeneratorTest(),
            new ShortenedDigestTest(),
            new EqualsHashCodeTest(),
            new TEATest(),
            new XTEATest(),
            new RFC3211WrapTest(),
            new SEEDTest(),
            new Salsa20Test(),
            new XSalsa20Test(),
            new ChaChaTest(),
            new ChaCha20Poly1305Test(),
            new CMacTest(),
            new EAXTest(),
            new GCMTest(),
            new GMacTest(),
            new HCFamilyTest(),
            new HCFamilyVecTest(),
            new ISAACTest(),
            new NoekeonTest(),
            new VMPCKSA3Test(),
            new VMPCMacTest(),
            new VMPCTest(),
            new Grainv1Test(),
            new Grain128Test(),
            //new NaccacheSternTest(),
            new SRP6Test(),
            new SCryptTest(),
            new ResetTest(),
            new NullTest(),
            new DSTU4145Test(),
            new SipHashTest(),
            new Poly1305Test(),
            new OCBTest(),
            new NonMemoableDigestTest(),
            new RSAKeyEncapsulationTest(),
            new ECIESKeyEncapsulationTest(),
            new HashCommitmentTest(),
            new CipherStreamTest(),
            new BlockCipherResetTest(),
            new StreamCipherResetTest(),
            new SM3DigestTest(),
            new Shacal2Test(),
            new KDFCounterGeneratorTest(),
            new KDFDoublePipelineIteratorGeneratorTest(),
            new KDFFeedbackGeneratorTest(),
            new CramerShoupTest(),
            new BCryptTest(),
            new OpenBSDBCryptTest(),
            new X931SignerTest(),
            new Blake2bDigestTest(),
            new Blake2sDigestTest(),
            new Blake2xsDigestTest(),
            new KeccakDigestTest(),
            new SHAKEDigestTest(),
            new SM2EngineTest(),
            new SM2KeyExchangeTest(),
            new SM2SignerTest(),
            new SM4Test(),
            new DSTU7624Test(),
            new DSTU7564Test(),
            new IsoTrailerTest(),
            new GOST3412Test(),
            new GOST3412MacTest(),
            new GSKKDFTest(),
            new X25519Test(),
            new X448Test(),
            new Ed25519Test(),
            new Ed448Test(),
            new CSHAKETest(),
            new Argon2Test(),
            new OpenSSHKeyParsingTests(),
            new EthereumIESTest(),
            new BigIntegersTest(),
            new ZucTest(),
            new Haraka256DigestTest(),
            new Haraka512DigestTest(),
            new KMACTest(),
            new SipHash128Test(),
            new GCMSIVTest(),
            new Blake3Test(),
            new KangarooTest(),
            new SP80038GTest(),
            new TupleHashTest(),
            new ParallelHashTest(),
            new CryptoServiceConstraintsTest(),
            new SymmetricConstraintsTest(),
            new DigestConstraintsTest(),
            new RadixConverterTest(),
            new Grain128AEADTest()
        };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
