package com.distrimind.bouncycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;

import com.distrimind.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import com.distrimind.bouncycastle.crypto.digests.SHA1Digest;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.AlertLevel;
import com.distrimind.bouncycastle.tls.BasicTlsSRPIdentity;
import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SRPTlsServer;
import com.distrimind.bouncycastle.tls.SignatureAlgorithm;
import com.distrimind.bouncycastle.tls.SimulatedTlsSRPIdentityManager;
import com.distrimind.bouncycastle.tls.TlsCredentialedSigner;
import com.distrimind.bouncycastle.tls.TlsSRPIdentity;
import com.distrimind.bouncycastle.tls.TlsSRPIdentityManager;
import com.distrimind.bouncycastle.tls.TlsSRPLoginParameters;
import com.distrimind.bouncycastle.tls.crypto.SRP6Group;
import com.distrimind.bouncycastle.tls.crypto.SRP6StandardGroups;
import com.distrimind.bouncycastle.tls.crypto.TlsCrypto;
import com.distrimind.bouncycastle.tls.crypto.TlsSRPConfig;
import com.distrimind.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Strings;

class MockSRPTlsServer
    extends SRPTlsServer
{
    static final SRP6Group TEST_GROUP = SRP6StandardGroups.rfc5054_1024;
    static final byte[] TEST_IDENTITY = Strings.toUTF8ByteArray("client");
    static final byte[] TEST_PASSWORD = Strings.toUTF8ByteArray("password");
    static final TlsSRPIdentity TEST_SRP_IDENTITY = new BasicTlsSRPIdentity(TEST_IDENTITY, TEST_PASSWORD);
    static final byte[] TEST_SALT = Strings.toUTF8ByteArray("salt");
    static final byte[] TEST_SEED_KEY = Strings.toUTF8ByteArray("seed_key");

    MockSRPTlsServer()
        throws IOException
    {
        super(new BcTlsCrypto(new SecureRandom()), new MyIdentityManager(new BcTlsCrypto(new SecureRandom())));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server raised alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] srpIdentity = context.getSecurityParametersConnection().getSRPIdentity();
        if (srpIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(srpIdentity);
            System.out.println("TLS-SRP server completed handshake for SRP identity: " + name);
        }
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-SRP server negotiated " + serverVersion);

        return serverVersion;
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentials(context, clientSigAlgs, SignatureAlgorithm.dsa, "x509-server-dsa.pem",
            "x509-server-key-dsa.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();
        return TlsTestUtils.loadSignerCredentialsServer(context, clientSigAlgs, SignatureAlgorithm.rsa);
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.TLSv12.only();
    }

    static class MyIdentityManager
        implements TlsSRPIdentityManager
    {
        protected SimulatedTlsSRPIdentityManager unknownIdentityManager;

        MyIdentityManager(TlsCrypto crypto)
            throws IOException
        {
            unknownIdentityManager = SimulatedTlsSRPIdentityManager.getRFC5054Default(crypto, TEST_GROUP, TEST_SEED_KEY);
        }

        public TlsSRPLoginParameters getLoginParameters(byte[] identity)
        {
            if (Arrays.areEqual(TEST_IDENTITY, identity))
            {
                SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
                verifierGenerator.init(TEST_GROUP.getN(), TEST_GROUP.getG(), new SHA1Digest());

                BigInteger verifier = verifierGenerator.generateVerifier(TEST_SALT, identity, TEST_PASSWORD);

                TlsSRPConfig srpConfig = new TlsSRPConfig();
                srpConfig.setExplicitNG(new BigInteger[]{ TEST_GROUP.getN(), TEST_GROUP.getG() });

                return new TlsSRPLoginParameters(identity, srpConfig, verifier, TEST_SALT);
            }

            return unknownIdentityManager.getLoginParameters(identity);
        }
    }
}
