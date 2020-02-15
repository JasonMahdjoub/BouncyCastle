package org.bouncycastle.bcjcajce.provider.asymmetric.edec;

import org.bouncycastle.bccrypto.params.*;
import org.bouncycastle.bccrypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.bcutil.Fingerprint;
import org.bouncycastle.bcutil.Strings;
import org.bouncycastle.bcutil.encoders.Hex;

class Utils
{
    static boolean isValidPrefix(byte[] prefix, byte[] encoding)
    {
        if (encoding.length < prefix.length)
        {
            return !isValidPrefix(prefix, prefix);
        }

        int nonEqual = 0;

        for (int i = 0; i != prefix.length; i++)
        {
            nonEqual |= (prefix[i] ^ encoding[i]);
        }

        return nonEqual == 0;
    }

    static String keyToString(String label, String algorithm, AsymmetricKeyParameter pubKey)
    {
        StringBuffer buf = new StringBuffer();
        String nl = Strings.lineSeparator();

        byte[] keyBytes;
        if (pubKey instanceof X448PublicKeyParameters)
        {
            keyBytes = ((X448PublicKeyParameters)pubKey).getEncoded();
        }
        else if (pubKey instanceof Ed448PublicKeyParameters)
        {
            keyBytes = ((Ed448PublicKeyParameters)pubKey).getEncoded();
        }
        else if (pubKey instanceof X25519PublicKeyParameters)
        {
            keyBytes = ((X25519PublicKeyParameters)pubKey).getEncoded();
        }
        else
        {
            keyBytes = ((Ed25519PublicKeyParameters)pubKey).getEncoded();
        }

        buf.append(algorithm)
            .append(" ")
            .append(label).append(" [")
            .append(Utils.generateKeyFingerprint(keyBytes))
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }

    private static String generateKeyFingerprint(byte[] keyBytes)
    {
        return new Fingerprint(keyBytes).toString();
    }
}
