package com.distrimind.bouncycastle.cms.test;

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
        Security.addProvider(new com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("BC");
    }
}
