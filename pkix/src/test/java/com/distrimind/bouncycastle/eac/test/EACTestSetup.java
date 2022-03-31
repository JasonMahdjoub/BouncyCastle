
package com.distrimind.bouncycastle.eac.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;

class EACTestSetup
    extends TestSetup
{
    public EACTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
