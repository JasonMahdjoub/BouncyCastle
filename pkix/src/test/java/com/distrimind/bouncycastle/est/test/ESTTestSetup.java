
package com.distrimind.bouncycastle.est.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;

class ESTTestSetup
    extends TestSetup
{
    public ESTTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

}
