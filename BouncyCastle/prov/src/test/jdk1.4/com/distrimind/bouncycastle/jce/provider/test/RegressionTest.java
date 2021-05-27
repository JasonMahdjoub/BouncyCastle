package com.distrimind.bouncycastle.jce.provider.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.test.SimpleTest;
import com.distrimind.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new FIPSDESTest(),
        new DESedeTest(),
        new AESTest(),
        new AESSICTest(),
        new GOST28147Test(),
        new PBETest(),
        new BlockCipherTest(),
        new MacTest(),
        new HMacTest(),
        new SealedTest(),
        new RSATest(),
        new DHTest(),
        new DSATest(),
        new ImplicitlyCaTest(),
        new GOST3410Test(),
        new ElGamalTest(),
        new ECIESTest(),
        new SigTest(),
        new CertTest(),
        new PKCS10CertRequestTest(),
        new EncryptedPrivateKeyInfoTest(),
        new KeyStoreTest(),
        new PKCS12StoreTest(),
        new DigestTest(),
        new PSSTest(),
        new WrapTest(),
        new DoFinalTest(),
        new CipherStreamTest(),
        new NamedCurveTest(),
        new PKIXTest(),
        new PKIXPolicyMappingTest(),
        new NetscapeCertRequestTest(),
        new CertPathTest(),
        new CertStoreTest(),
        new CertPathValidatorTest(),
        new CertPathBuilderTest(),
        new NISTCertPathTest(),
        new SerialisationTest(),
        new EdECTest()
    };

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Testing " + Security.getProvider("BC").getInfo() + " version: " + Security.getProvider("BC").getVersion());

        SimpleTest.runTests(tests);
    }
}
