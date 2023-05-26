package com.distrimind.bouncycastle.crypto;

public interface CryptoServiceProperties
{
    int bitsOfSecurity();

    String getServiceName();

    CryptoServicePurpose getPurpose();

    Object getParams();
}
