package org.bouncycastle.bccrypto.params;

import org.bouncycastle.bccrypto.CipherParameters;

public class ParametersWithUKMBC
    implements CipherParameters
{
    private byte[] ukm;
    private CipherParameters parameters;

    public ParametersWithUKMBC(
        CipherParameters parameters,
        byte[] ukm)
    {
        this(parameters, ukm, 0, ukm.length);
    }

    public ParametersWithUKMBC(
        CipherParameters parameters,
        byte[] ukm,
        int                 ivOff,
        int                 ivLen)
    {
        this.ukm = new byte[ivLen];
        this.parameters = parameters;

        System.arraycopy(ukm, ivOff, this.ukm, 0, ivLen);
    }

    public byte[] getUKM()
    {
        return ukm;
    }

    public CipherParameters getParameters()
    {
        return parameters;
    }
}
