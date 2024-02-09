package com.distrimind.bouncycastle.crypto.constraints;

import java.util.Collections;
import java.util.Set;

import com.distrimind.bouncycastle.crypto.CryptoServiceConstraintsException;
import com.distrimind.bouncycastle.crypto.CryptoServiceProperties;

/**
 * Basic bits of security constraint. Anything not of the required bits of security and
 * not in the exception list will be rejected.
 */
public class BitsOfSecurityConstraint
    extends ServicesConstraint
{
    private final int requiredBitsOfSecurity;

    public BitsOfSecurityConstraint(int requiredBitsOfSecurity)
    {
        super(Collections.EMPTY_SET);

        this.requiredBitsOfSecurity = requiredBitsOfSecurity;
    }

    public BitsOfSecurityConstraint(int requiredBitsOfSecurity, Set<String> exceptions)
    {
        super(exceptions);

        this.requiredBitsOfSecurity = requiredBitsOfSecurity;
    }

    public void check(CryptoServiceProperties service)
    {
        if (isException(service.getServiceName()))
        {
            return;
        }

        if (service.bitsOfSecurity() < requiredBitsOfSecurity)
        {
            throw new CryptoServiceConstraintsException("service does not provide " + requiredBitsOfSecurity + " bits of security only " + service.bitsOfSecurity());
        }
    }
}
