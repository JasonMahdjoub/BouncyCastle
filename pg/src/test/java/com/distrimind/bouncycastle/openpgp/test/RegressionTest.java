package com.distrimind.bouncycastle.openpgp.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[] tests = {
        new BcPGPKeyRingTest(),
        new PGPKeyRingTest(),
        new BcPGPRSATest(),
        new PGPRSATest(),
        new BcPGPDSATest(),
        new PGPDSATest(),
        new BcPGPDSAElGamalTest(),
        new PGPDSAElGamalTest(),
        new BcPGPPBETest(),
        new PGPPBETest(),
        new PGPMarkerTest(),
        new PGPPacketTest(),
        new PGPArmoredTest(),
        new PGPSignatureInvalidVersionIgnoredTest(),
        new PGPSignatureTest(),
        new PGPClearSignedSignatureTest(),
        new PGPCompressionTest(),
        new PGPNoPrivateKeyTest(),
        new PGPECDSATest(),
        new PGPECDHTest(),
        new PGPECMessageTest(),
        new PGPParsingTest(),
        new PGPEdDSATest(),
        new PGPPublicKeyMergeTest(),
        new SExprTest(),
        new PGPUtilTest(),
        new BcPGPEd25519JcaKeyPairConversionTest(),
        new RewindStreamWhenDecryptingMultiSKESKMessageTest(),
        new PGPFeaturesTest(),
        new ArmoredInputStreamTest(),
        new ArmoredInputStreamBackslashTRVFTest(),
        new ArmoredInputStreamCRCErrorGetsThrownTest(),
        new ArmoredInputStreamIngoreMissingCRCSum(),
        new ArmoredOutputStreamTest(),
        new PGPSessionKeyTest(),
        new PGPCanonicalizedDataGeneratorTest(),
        new RegexTest(),
        new PolicyURITest(),
        new ArmoredOutputStreamUTF8Test(),
        new UnrecognizableSubkeyParserTest(),
        new IgnoreUnknownEncryptedSessionKeys(),
        new PGPEncryptedDataTest(),
        new PGPAeadTest(),
        new CRC24Test(),
        new WildcardKeyIDTest(),
        new ArmorCRCTest(),
        new UnknownPacketTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        SimpleTest.runTests(tests);
    }
}
