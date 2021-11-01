package com.distrimind.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import com.distrimind.bouncycastle.math.ec.rfc7748.X25519;
import com.distrimind.bouncycastle.tls.AlertDescription;
import com.distrimind.bouncycastle.tls.TlsFatalAlert;
import com.distrimind.bouncycastle.tls.crypto.TlsAgreement;
import com.distrimind.bouncycastle.tls.crypto.TlsSecret;
import com.distrimind.bouncycastle.util.Arrays;

/**
 * Support class for X25519 using the BC light-weight library.
 */
public class BcX25519 implements TlsAgreement
{
    protected final BcTlsCrypto crypto;
    protected final byte[] privateKey = new byte[X25519.SCALAR_SIZE];
    protected final byte[] peerPublicKey = new byte[X25519.POINT_SIZE];

    public BcX25519(BcTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public byte[] generateEphemeral() throws IOException
    {
        crypto.getSecureRandom().nextBytes(privateKey);

        byte[] publicKey = new byte[X25519.POINT_SIZE];
        X25519.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        if (peerValue == null || peerValue.length != X25519.POINT_SIZE)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        System.arraycopy(peerValue, 0, peerPublicKey, 0, X25519.POINT_SIZE);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            byte[] secret = new byte[X25519.POINT_SIZE];
            if (!X25519.calculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            return crypto.adoptLocalSecret(secret);
        }
        finally
        {
            Arrays.fill(privateKey, (byte)0);
            Arrays.fill(peerPublicKey, (byte)0);
        }
    }
}
