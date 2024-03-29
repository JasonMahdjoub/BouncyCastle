package com.distrimind.bouncycastle.its.test;

import java.security.Security;

import junit.extensions.TestSetup;
import junit.framework.Test;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;

class ITSTestSetup
    extends TestSetup
{
    public ITSTestSetup(Test test)
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
