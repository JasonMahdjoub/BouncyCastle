package org.bouncycastle.bcutil.test;

public interface Test
{
    String getName();

    TestResult perform();
}
