// Copyright (c) 2005 The Legion Of The Bouncy Castle (https://www.bouncycastle.org)
package com.distrimind.bouncycastle.pkcs.test;

import java.security.Security;

import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;
import junit.extensions.TestSetup;
import junit.framework.Test;

class BCTestSetup
    extends TestSetup
{
    public BCTestSetup(Test test)
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
