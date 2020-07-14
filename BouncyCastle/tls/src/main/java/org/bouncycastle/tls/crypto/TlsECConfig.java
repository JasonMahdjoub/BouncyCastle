package com.distrimind.bouncycastle.tls.crypto;

import com.distrimind.bouncycastle.tls.NamedGroup;

/**
 * Carrier class for Elliptic Curve parameter configuration.
 */
public class TlsECConfig
{
    protected final int namedGroup;

    public TlsECConfig(int namedGroup)
    {
        this.namedGroup = namedGroup;
    }

    /**
     * Return the group used.
     *
     * @return the {@link NamedGroup named group} used.
     */
    public int getNamedGroup()
    {
        return namedGroup;
    }
}
