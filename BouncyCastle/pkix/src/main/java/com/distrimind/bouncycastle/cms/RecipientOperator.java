package com.distrimind.bouncycastle.cms;

import java.io.InputStream;
import java.io.OutputStream;

import com.distrimind.bouncycastle.operator.InputAEADDecryptor;
import com.distrimind.bouncycastle.operator.InputDecryptor;
import com.distrimind.bouncycastle.operator.MacCalculator;
import com.distrimind.bouncycastle.util.io.TeeInputStream;

public class RecipientOperator
{
    private final Object operator;

    public RecipientOperator(InputDecryptor decryptor)
    {
        this.operator = decryptor;
    }

    public RecipientOperator(MacCalculator macCalculator)
    {
        this.operator = macCalculator;
    }

    public InputStream getInputStream(InputStream dataIn)
    {
        if (operator instanceof InputDecryptor)
        {
            return ((InputDecryptor)operator).getInputStream(dataIn);
        }
        else
        {
            return new TeeInputStream(dataIn, ((MacCalculator)operator).getOutputStream());
        }
    }

    public boolean isAEADBased()
    {
        return operator instanceof InputAEADDecryptor;
    }

    public OutputStream getAADStream()
    {
        return ((InputAEADDecryptor)operator).getAADStream();
    }

    public boolean isMacBased()
    {
        return operator instanceof MacCalculator;
    }

    public byte[] getMac()
    {
        return ((MacCalculator)operator).getMac();
    }
}
