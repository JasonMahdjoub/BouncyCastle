package com.distrimind.bouncycastle.jcajce.provider.test;

import java.security.SecureRandom;
import java.security.Security;

import junit.framework.TestCase;
import com.distrimind.bouncycastle.jce.provider.BouncyCastleProvider;

public class HybridRandomProviderTest
    extends TestCase
{
    public void testCheckForStackOverflow()
    {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        new SecureRandom("not so random bytes".getBytes());
    }
}
