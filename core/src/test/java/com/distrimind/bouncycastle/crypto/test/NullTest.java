package com.distrimind.bouncycastle.crypto.test;

import com.distrimind.bouncycastle.crypto.BlockCipher;
import com.distrimind.bouncycastle.crypto.DataLengthException;
import com.distrimind.bouncycastle.crypto.engines.NullEngine;
import com.distrimind.bouncycastle.crypto.params.KeyParameter;
import com.distrimind.bouncycastle.util.encoders.Hex;
import com.distrimind.bouncycastle.util.test.SimpleTest;

public class NullTest 
    extends CipherTest
{
    static SimpleTest[]  tests = 
    {
        new BlockCipherVectorTest(0, new NullEngine(),
                new KeyParameter(Hex.decode("00")), "00", "00")
    };
    
    NullTest()
    {
        super(tests, new NullEngine(), new KeyParameter(new byte[2]));
    }

    public String getName()
    {
        return "Null";
    }

    public void performTest()
        throws Exception
    {
        super.performTest();
        
        BlockCipher engine = new NullEngine();
        
        engine.init(true, null);
        
        byte[] buf = new byte[1];
        
        engine.processBlock(buf, 0, buf, 0);
        
        if (buf[0] != 0)
        {
            fail("NullCipher changed data!");
        }
        
        byte[] shortBuf = new byte[0];
        
        try
        {   
            engine.processBlock(shortBuf, 0, buf, 0);
            
            fail("failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(buf, 0, shortBuf, 0);
            
            fail("failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
    }
    
    public static void main(
        String[]    args)
    {
        runTest(new NullTest());
    }
}
