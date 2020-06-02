package org.bouncycastle.bccrypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.bcasn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcasn1.x9.ECNamedCurveTable;
import org.bouncycastle.bcasn1.x9.X9ECParameters;
import org.bouncycastle.bccrypto.AsymmetricCipherKeyPair;
import org.bouncycastle.bccrypto.DataLengthException;
import org.bouncycastle.bccrypto.Digest;
import org.bouncycastle.bccrypto.digests.TigerDigest;
import org.bouncycastle.bccrypto.generators.ECKeyPairGenerator;
import org.bouncycastle.bccrypto.params.ECDomainParameters;
import org.bouncycastle.bccrypto.params.ECKeyGenerationParameters;
import org.bouncycastle.bccrypto.params.ECNamedDomainParameters;
import org.bouncycastle.bccrypto.params.ECPrivateKeyParameters;
import org.bouncycastle.bccrypto.params.ECPublicKeyParameters;
import org.bouncycastle.bccrypto.params.ParametersWithRandom;
import org.bouncycastle.bccrypto.signers.ECNRSigner;
import org.bouncycastle.bcmath.ec.ECConstants;
import org.bouncycastle.bcmath.ec.ECCurve;
import org.bouncycastle.bcutil.Arrays;
import org.bouncycastle.bcutil.BigIntegers;
import org.bouncycastle.bcutil.encoders.Hex;
import org.bouncycastle.bcutil.test.SimpleTest;
import org.bouncycastle.bcutil.test.TestRandomBigInteger;

/**
 * ECNR tests.
 */
public class ECNRTest
    extends SimpleTest
{
    /**
     * a basic regression test with 239 bit prime
     */
    BigInteger r = new BigInteger("308636143175167811492623515537541734843573549327605293463169625072911693");
    BigInteger s = new BigInteger("852401710738814635664888632022555967400445256405412579597015412971797143");

    byte[] kData = BigIntegers.asUnsignedByteArray(new BigInteger("700000017569056646655505781757157107570501575775705779575555657156756655"));

    SecureRandom k = new TestRandomBigInteger(kData);

    private void ecNR239bitPrime()
    {
        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");

        ECCurve.Fp curve = new ECCurve.Fp(
            new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16), // b
            n, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            n);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("876300101507107567501066130761671078357010671067781776716671676178726717"), // d
            params);

        ECNRSigner ecnr = new ECNRSigner();
        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ecnr.init(true, param);

        byte[] message = new BigInteger("968236873715988614170569073515315707566766479517").toByteArray();
        BigInteger[] sig = ecnr.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong.", r, sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong.", s, sig[1]);
        }

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.decodePoint(Hex.decode("025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70")), // Q
            params);

        ecnr.init(false, pubKey);
        if (!ecnr.verifySignature(message, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    private void rangeTest()
    {
        /* Create the generator */
        ECKeyPairGenerator myGenerator = new ECKeyPairGenerator();
        SecureRandom myRandom = new SecureRandom();
        String myCurve = "brainpoolP192t1";

        /* Lookup the parameters */
        final X9ECParameters x9 = ECNamedCurveTable.getByName(myCurve);

        /* Initialise the generator */
        final ASN1ObjectIdentifier myOid = ECNamedCurveTable.getOID(myCurve);
        ECNamedDomainParameters myDomain = new ECNamedDomainParameters(myOid, x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        ECKeyGenerationParameters myParams = new ECKeyGenerationParameters(myDomain, myRandom);
        myGenerator.init(myParams);

        /* Create the key Pair */
        AsymmetricCipherKeyPair myPair = myGenerator.generateKeyPair();

        /* Create the digest and the output buffer */
        Digest myDigest = new TigerDigest();
        byte[] myArtifact = new byte[myDigest.getDigestSize()];
        final byte[] myMessage = "Hello there. How is life treating you?".getBytes();
        myDigest.update(myMessage, 0, myMessage.length);
        myDigest.doFinal(myArtifact, 0);

        /* Create signer */
        ECNRSigner signer = new ECNRSigner();
        signer.init(true, myPair.getPrivate());

        try
        {
            signer.generateSignature(myArtifact);
            fail("out of range input not caught");
        }
        catch (DataLengthException e)
        {
            isTrue(e.getMessage().equals("input too large for ECNR key"));
        }

        //
        // check upper bound
        BigInteger order = ((ECPublicKeyParameters)myPair.getPublic()).getParameters().getN();

        signer.init(true, myPair.getPrivate());
        byte[] msg = BigIntegers.asUnsignedByteArray(order.subtract(BigIntegers.ONE));
        BigInteger[] sig = signer.generateSignature(msg);

        signer.init(false, myPair.getPublic());
        if (!signer.verifySignature(msg, sig[0], sig[1]))
        {
            fail("ECNR failed 2");
        }

        isTrue(Arrays.areEqual(msg, signer.getRecoveredMessage(sig[0], sig[1])));
    }

    public String getName()
    {
        return "ECNR";
    }

    public void performTest()
    {
        ecNR239bitPrime();
        rangeTest();
    }

    public static void main(
        String[] args)
    {
        runTest(new ECNRTest());
    }
}

