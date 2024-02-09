package com.distrimind.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.distrimind.bouncycastle.asn1.ASN1EncodableVector;
import com.distrimind.bouncycastle.asn1.ASN1Integer;
import com.distrimind.bouncycastle.asn1.ASN1Object;
import com.distrimind.bouncycastle.asn1.ASN1Primitive;
import com.distrimind.bouncycastle.asn1.DEROctetString;
import com.distrimind.bouncycastle.asn1.DERSequence;
import com.distrimind.bouncycastle.jcajce.provider.symmetric.util.GcmSpecUtil;
import com.distrimind.bouncycastle.jcajce.spec.AEADParameterSpec;
import com.distrimind.bouncycastle.util.Arrays;

public class JceAEADCipherUtil
{
    static void setUpAeadCipher(Cipher aead, SecretKey secretKey, int mode, byte[] nonce, int aeadMacLen, byte[] aad)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (GcmSpecUtil.gcmSpecExtractable())
        {
            AlgorithmParameterSpec parameters;
            try
            {
                parameters = GcmSpecUtil.extractGcmSpec(new GCMParameters(nonce, (aeadMacLen + 7) / 8).toASN1Primitive());
            }
            catch (InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException(e.getMessage());
            }
            aead.init(mode, secretKey, parameters);
            aead.updateAAD(aad);
        }
        else
        {
            AEADParameterSpec parameters = new AEADParameterSpec(nonce, aeadMacLen, aad);
            aead.init(mode, secretKey, parameters);
        }
    }

    static class GCMParameters
        extends ASN1Object
    {
        private byte[] nonce;
        private int icvLen;

        public GCMParameters(
            byte[] nonce,
            int    icvLen)
        {
            this.nonce = Arrays.clone(nonce);
            this.icvLen = icvLen;
        }

        public byte[] getNonce()
        {
            return Arrays.clone(nonce);
        }

        public int getIcvLen()
        {
            return icvLen;
        }

        public ASN1Primitive toASN1Primitive()
        {
            ASN1EncodableVector v = new ASN1EncodableVector(2);

            v.add(new DEROctetString(nonce));

            if (icvLen != 12)
            {
                v.add(new ASN1Integer(icvLen));
            }

            return new DERSequence(v);
        }
    }
}
