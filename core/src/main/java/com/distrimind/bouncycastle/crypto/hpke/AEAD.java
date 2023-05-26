package com.distrimind.bouncycastle.crypto.hpke;

import com.distrimind.bouncycastle.crypto.engines.AESEngine;
import com.distrimind.bouncycastle.crypto.modes.AEADCipher;
import com.distrimind.bouncycastle.crypto.modes.ChaCha20Poly1305;
import com.distrimind.bouncycastle.crypto.modes.GCMBlockCipher;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.crypto.params.ParametersWithIV;
import com.distrimind.bouncycastle.crypto.CipherParameters;
import com.distrimind.bouncycastle.crypto.InvalidCipherTextException;
import com.distrimind.bouncycastle.util.Arrays;
import com.distrimind.bouncycastle.util.Pack;

public class AEAD
{

    private final short aeadId;
    private final byte[] key;
    private final byte[] baseNonce;
    private long seq = 0; // todo throw exception if overflow

    private AEADCipher cipher;

    public AEAD(short aeadId, byte[] key, byte[] baseNonce)
    {
        this.key = key;
        this.baseNonce = baseNonce;
        this.aeadId = aeadId;
        seq = 0;

        switch (aeadId)
        {
        case HPKE.aead_AES_GCM128:
        case HPKE.aead_AES_GCM256:
            cipher = new GCMBlockCipher(new AESEngine());
            break;
        case HPKE.aead_CHACHA20_POLY1305:
            cipher = new ChaCha20Poly1305();
            break;
        case HPKE.aead_EXPORT_ONLY:
            break;
        }
    }


    // used by Sender
    public byte[] seal(byte[] aad, byte[] pt)
            throws InvalidCipherTextException
    {
        CipherParameters params;
        switch (aeadId)
        {
            case HPKE.aead_AES_GCM128:
            case HPKE.aead_AES_GCM256:
            case HPKE.aead_CHACHA20_POLY1305:
                params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
                break;
            case HPKE.aead_EXPORT_ONLY:
            default:
                throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }
        cipher.init(true, params);
        cipher.processAADBytes(aad, 0, aad.length);
        byte[] ct = new byte[cipher.getOutputSize(pt.length)];
        int len = cipher.processBytes(pt, 0, pt.length, ct, 0);
        cipher.doFinal(ct, len);

        seq++;
        return ct;
    }


    // used by Receiver
    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        CipherParameters params;
        switch (aeadId)
        {
            case HPKE.aead_AES_GCM128:
            case HPKE.aead_AES_GCM256:
            case HPKE.aead_CHACHA20_POLY1305:
                params = new ParametersWithIV(new KeyParameter(key), ComputeNonce());
                break;
            case HPKE.aead_EXPORT_ONLY:
            default:
                throw new IllegalStateException("Export only mode, cannot be used to seal/open");
        }

        cipher.init(false, params);
        cipher.processAADBytes(aad, 0, aad.length);

        byte[] pt = new byte[cipher.getOutputSize(ct.length)];
        int len = cipher.processBytes(ct, 0, ct.length, pt, 0);
        len += cipher.doFinal(pt, len);

        seq++;
        return pt;
    }

    private byte[] ComputeNonce()
    {
        byte[] seq_bytes = Pack.longToBigEndian(seq);
        int Nn = baseNonce.length;
        byte[] nonce = Arrays.clone(baseNonce);
        //xor
        for (int i = 0; i < 8; i++)
        {
            nonce[Nn-8+i] ^= seq_bytes[i];
        }
        return nonce;
    }


}

