package com.distrimind.bouncycastle.cms.test;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import junit.extensions.TestSetup;
import junit.framework.Test;

import java.security.Security;

class CMSTestSetup extends TestSetup
{
    public CMSTestSetup(Test test)
    {
        super(test);
    }

    protected void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("BC");
    }
}
