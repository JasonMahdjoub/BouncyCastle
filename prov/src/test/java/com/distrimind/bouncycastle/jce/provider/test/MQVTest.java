package com.distrimind.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

import com.distrimind.bouncycastle.jcajce.spec.MQVParameterSpec;
import com.distrimind.bouncycastle.jce.ECPointUtil;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class MQVTest
    extends SimpleTest
{
    public String getName()
    {
        return "MQV";
    }

    public void performTest()
        throws Exception
    {
        testECMQV();
    }

    private void testECMQV()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECMQV", "BC");

        EllipticCurve curve = new EllipticCurve(
                new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
                1); // h

        g.initialize(ecSpec, new SecureRandom());

         //
        // U side
        //
        KeyPair U1 = g.generateKeyPair();
        KeyPair U2 = g.generateKeyPair();

        //
        // V side
        //
        KeyPair V1 = g.generateKeyPair();
        KeyPair V2 = g.generateKeyPair();

        KeyAgreement uAgree = KeyAgreement.getInstance("ECMQV", "BC");
        uAgree.init(U1.getPrivate(), new MQVParameterSpec(U2, V2.getPublic()));

        KeyAgreement vAgree = KeyAgreement.getInstance("ECMQV", "BC");
        vAgree.init(V1.getPrivate(), new MQVParameterSpec(V2, U2.getPublic()));

        //
        // agreement
        //
        uAgree.doPhase(V1.getPublic(), true);
        vAgree.doPhase(U1.getPublic(), true);

        BigInteger ux = new BigInteger(uAgree.generateSecret());
        BigInteger vx = new BigInteger(vAgree.generateSecret());

        if (!ux.equals(vx))
        {
            fail("Agreement failed");
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MQVTest());
    }
}
