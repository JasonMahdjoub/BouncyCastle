package com.distrimind.bouncycastle.jsse.provider;

import com.distrimind.bouncycastle.tls.DefaultTlsDHGroupVerifier;
import com.distrimind.bouncycastle.tls.crypto.DHGroup;

class ProvDHGroupVerifier
    extends DefaultTlsDHGroupVerifier
{
    private static final int provMinimumPrimeBits = PropertyUtils.getIntegerSystemProperty("com.distrimind.bouncycastle.jsse.client.dh.minimumPrimeBits", 2048, 1024, 16384);
    private static final boolean provUnrestrictedGroups = PropertyUtils.getBooleanSystemProperty("com.distrimind.bouncycastle.jsse.client.dh.unrestrictedGroups", false);

    ProvDHGroupVerifier()
    {
        super(provMinimumPrimeBits);
    }

    @Override
    protected boolean checkGroup(DHGroup dhGroup)
    {
        return provUnrestrictedGroups || super.checkGroup(dhGroup);
    }
}
