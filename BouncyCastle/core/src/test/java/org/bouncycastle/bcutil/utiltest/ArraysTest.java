package org.bouncycastle.bcutil.utiltest;

import junit.framework.TestCase;
import org.bouncycastle.bcutil.Arrays;

public class ArraysTest
    extends TestCase
{
    public void testConcatenate()
    {
        assertNull(Arrays.concatenate((byte[])null, (byte[])null));
        assertNull(Arrays.concatenate((int[])null, (int[])null));
    }
}
