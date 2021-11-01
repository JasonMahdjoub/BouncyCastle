package com.distrimind.bouncycastle.asn1.its;

import com.distrimind.bouncycastle.util.Arrays;

class Utils
{
    /**
     * <pre>
     *     OCTET STRING (SIZE(n))
     * </pre>
     */
    static byte[] octetStringFixed(byte[] octets, int n)
    {
        if (octets.length != n)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return octets;
    }

    /**
     * <pre>
     *     OCTET STRING (SIZE(1..32))
     * </pre>
     */
    static byte[] octetStringFixed(byte[] octets)
    {
        if (octets.length < 1 || octets.length > 32)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return Arrays.clone(octets);
    }
}
