package com.distrimind.bouncycastle.crypto.signers;

import java.io.ByteArrayOutputStream;

import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.CryptoServicesRegistrar;
import com.distrimind.bouncycastle.crypto.Signer;
import com.distrimind.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import com.distrimind.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import com.distrimind.bouncycastle.crypto.params.ParametersWithRandom;
import com.distrimind.bouncycastle.math.ec.rfc8032.Ed25519;
import com.distrimind.bouncycastle.util.Arrays;

public class Ed25519Signer
    implements Signer
{
    private final Buffer buffer = new Buffer();

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519Signer()
    {
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;
        if (parameters instanceof ParametersWithRandom)
        {
            parameters = ((ParametersWithRandom)parameters).getParameters();
        }
        if (forSigning)
        {
            this.privateKey = (Ed25519PrivateKeyParameters)parameters;
            this.publicKey = null;
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters)parameters;
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("Ed25519", 128, parameters, forSigning));
        
        reset();
    }

    public void update(byte b)
    {
        buffer.write(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        buffer.write(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed25519Signer not initialised for signature generation.");
        }

        return buffer.generateSignature(privateKey);
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519Signer not initialised for verification");
        }

        return buffer.verifySignature(publicKey, signature);
    }

    public void reset()
    {
        buffer.reset();
    }

    private static final class Buffer extends ByteArrayOutputStream
    {
        synchronized byte[] generateSignature(Ed25519PrivateKeyParameters privateKey)
        {
            byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
            privateKey.sign(Ed25519.Algorithm.Ed25519, null, buf, 0, count, signature, 0);
            reset();
            return signature;
        }

        synchronized boolean verifySignature(Ed25519PublicKeyParameters publicKey, byte[] signature)
        {
            if (Ed25519.SIGNATURE_SIZE != signature.length)
            {
                reset();
                return false;
            }

            boolean result = publicKey.verify(Ed25519.Algorithm.Ed25519, null, buf, 0, count, signature, 0);
            reset();
            return result;
        }

        public synchronized void reset()
        {
            Arrays.fill(buf, 0, count, (byte)0);
            this.count = 0;
        }
    }
}
